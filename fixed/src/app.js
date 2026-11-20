// Pocket Notes, fixed. Each "FIX" comment names the lesson that explains it.
import express from 'express';
import helmet from 'helmet';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { openDb, hashPassword, verifyPassword, DUMMY_HASH } from './db.js';
import { config } from './config.js';
import * as views from './views.js';

const COMMON_PASSWORDS = new Set(['passwordpassword', '123456789012345', 'qwertyuiopasdfgh', 'iloveyouiloveyou', 'letmeinletmein1']);
const SESSION_IDLE_MS = 30 * 60 * 1000; // 30 minutes without a request
const SESSION_MAX_MS = 8 * 60 * 60 * 1000; // 8 hours after login, whatever happens

export function createApp({ db = openDb(), log = console.log } = {}) {
  const app = express();

  // FIX (lesson 10): security headers on every response, X-Powered-By removed.
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'"],
        'font-src': ["'self'"], // helmet's default also allows https: and data:, which ZAP reports as a wildcard
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));
  // A request id first, so even a body that fails to parse can be matched to its log line.
  app.use((req, res, next) => {
    req.id = randomUUID();
    next();
  });
  app.use('/static', express.static(path.join(import.meta.dirname, '..', 'public')));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use(express.json({ limit: '10kb' }));

  // ---------- sessions (FIX lesson 5) ----------
  const sessions = new Map(); // sid -> { userId, csrf, createdAt, seenAt }
  const cookies = (req) =>
    Object.fromEntries((req.headers.cookie ?? '').split(';').filter((c) => c.includes('=')).map((c) => {
      const i = c.indexOf('=');
      return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
    }));
  const cookieOptions = { httpOnly: true, sameSite: 'lax', secure: true, path: '/', maxAge: SESSION_MAX_MS };

  function startSession(res, userId) {
    const sid = randomBytes(32).toString('base64url'); // 256 random bits, never reused
    sessions.set(sid, { userId, csrf: randomBytes(32).toString('base64url'), createdAt: Date.now(), seenAt: Date.now() });
    res.cookie('sid', sid, cookieOptions);
  }

  // Load the session named by the cookie. Sessions idle too long, or too old, are deleted.
  app.use((req, res, next) => {
    const sid = cookies(req).sid;
    const s = sid && sessions.get(sid);
    const now = Date.now();
    if (s && (now - s.seenAt > SESSION_IDLE_MS || now - s.createdAt > SESSION_MAX_MS)) sessions.delete(sid);
    else if (s) {
      s.seenAt = now;
      req.sid = sid;
      req.session = s;
      req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(s.userId);
    }
    next();
  });

  // ---------- CORS (FIX lesson 9): only origins on the allowlist get CORS headers ----------
  app.use('/api', (req, res, next) => {
    const origin = req.headers.origin;
    res.set('Vary', 'Origin'); // caches must not reuse one origin's answer for another
    if (origin && config.allowedOrigins.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Access-Control-Allow-Credentials', 'true');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
      res.set('Access-Control-Allow-Headers', 'Content-Type');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  // ---------- CSRF (FIX lesson 9) ----------
  const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const sameToken = (a, b) => typeof a === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
  app.use((req, res, next) => {
    if (!UNSAFE.has(req.method) || !req.session) return next(); // no session cookie, nothing to forge
    const forbid = (why) => {
      log('[csrf] blocked', { path: req.path, why, requestId: req.id });
      return req.path.startsWith('/api') ? res.status(403).json({ error: 'Forbidden' }) : res.status(403).type('text').send('Forbidden');
    };
    if (req.headers['sec-fetch-site'] === 'cross-site') return forbid('Sec-Fetch-Site: cross-site');
    const origin = req.headers.origin;
    if (origin && !config.allowedOrigins.includes(origin)) return forbid(`Origin ${origin}`);
    if (req.path.startsWith('/api')) {
      // A cross-site HTML form cannot send application/json without a CORS preflight.
      if (req.method !== 'DELETE' && !req.is('application/json')) return forbid('API call without a JSON body');
      return next();
    }
    if (!sameToken(req.body?._csrf, req.session.csrf)) return forbid('missing or wrong CSRF token');
    next();
  });

  const needLogin = (req, res, next) => {
    if (!req.user) return req.originalUrl.startsWith('/api') ? res.status(401).json({ error: 'Log in first' }) : res.redirect('/login');
    next();
  };
  // FIX (lesson 6): the role check runs on the server for every admin route.
  const needRole = (role) => (req, res, next) => {
    if (req.user?.role !== role) {
      return req.originalUrl.startsWith('/api') ? res.status(403).json({ error: 'Forbidden' }) : res.status(403).type('text').send('Forbidden');
    }
    next();
  };
  const page = (res, title, req, body) => res.type('html').send(views.layout(title, req.user, body, req.session?.csrf));

  // ---------- authentication (FIX lesson 4) ----------
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5, // 5 failed attempts per IP address and email in 15 minutes
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => `${ipKeyGenerator(req.ip)}|${String(req.body?.email ?? '').toLowerCase()}`,
    handler: (req, res) => {
      log('[login] rate limited', { email: req.body?.email, ip: req.ip });
      res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    },
  });
  // A second, wider limit per IP address: stops one machine trying one password on many accounts.
  const loginIpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' }),
  });
  const GENERIC = 'Email or password is incorrect.';
  function login(email, password) {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email ?? ''));
    const ok = verifyPassword(String(password ?? ''), user?.password_hash ?? DUMMY_HASH) && Boolean(user);
    log('[login]', { email, ok }); // FIX (lesson 11): the outcome is logged, the password never is
    return ok ? { user } : { error: GENERIC };
  }
  app.get('/login', (req, res) => page(res, 'Log in', req, views.loginPage()));
  app.post('/login', loginIpLimiter, loginLimiter, (req, res) => {
    const { user, error } = login(req.body.email, req.body.password);
    if (error) return page(res.status(401), 'Log in', req, views.loginPage(error));
    if (req.sid) sessions.delete(req.sid); // FIX (lesson 5): a fresh session id at login
    startSession(res, user.id);
    res.redirect('/notes');
  });
  app.post('/api/login', loginIpLimiter, loginLimiter, (req, res) => {
    const { user, error } = login(req.body?.email, req.body?.password);
    if (error) return res.status(401).json({ error });
    if (req.sid) sessions.delete(req.sid);
    startSession(res, user.id);
    res.json({ id: user.id, email: user.email, displayName: user.display_name, role: user.role });
  });
  // FIX (lesson 5): logout deletes the session on the server, not only the cookie.
  const logout = (req, res) => {
    if (req.sid) sessions.delete(req.sid);
    res.clearCookie('sid', { ...cookieOptions, maxAge: undefined });
  };
  app.post('/logout', (req, res) => { logout(req, res); res.redirect('/login'); });
  app.post('/api/logout', (req, res) => { logout(req, res); res.json({ ok: true }); });

  app.post('/api/register', rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false }), (req, res) => {
    const { email, password, displayName } = req.body ?? {};
    if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(email) || email.length > 254) return res.status(400).json({ error: 'A valid email is required.' });
    if (typeof password !== 'string' || password.length < 15 || password.length > 128) return res.status(400).json({ error: 'Use a password of 15 to 128 characters.' });
    if (COMMON_PASSWORDS.has(password.toLowerCase())) return res.status(400).json({ error: 'That password is too common.' });
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
      // Same answer as a new account: registration must not reveal who has an account either.
      return res.status(202).json({ message: 'Check your inbox to finish signing up.' });
    }
    db.prepare('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)')
      .run(email, String(displayName ?? email).slice(0, 60), hashPassword(password));
    log('[mail] welcome email queued', { to: email }); // the API key stays in memory, never in a log line
    res.status(202).json({ message: 'Check your inbox to finish signing up.' });
  });

  // ---------- notes: one helper decides who may see or change a note (FIX lesson 6) ----------
  function findNote(user, id, { write = false } = {}) {
    if (!/^\d+$/.test(String(id))) return undefined;
    const sql = write
      ? 'SELECT * FROM notes WHERE id = ? AND owner_id = ?'
      : `SELECT * FROM notes WHERE id = ? AND (owner_id = ?
           OR EXISTS (SELECT 1 FROM shares s WHERE s.note_id = notes.id AND s.user_id = ?))`;
    return write ? db.prepare(sql).get(id, user.id) : db.prepare(sql).get(id, user.id, user.id);
  }

  app.get('/', (req, res) => res.redirect(req.user ? '/notes' : '/login'));
  app.get('/notes', needLogin, (req, res) => {
    const notes = db.prepare('SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id').all(req.user.id);
    page(res, 'Notes', req, views.notesPage(notes, req.session.csrf));
  });
  app.post('/notes', needLogin, (req, res) => {
    const r = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)').run(req.user.id, String(req.body.title ?? ''), String(req.body.body ?? ''));
    res.redirect(`/notes/${r.lastInsertRowid}`);
  });
  app.get('/notes/:id', needLogin, (req, res) => {
    const note = findNote(req.user, req.params.id);
    if (!note) return page(res.status(404), 'Not found', req, '<h1>Note not found</h1>');
    page(res, note.title, req, views.notePage(note, req.session.csrf));
  });
  app.post('/notes/:id/delete', needLogin, (req, res) => {
    const note = findNote(req.user, req.params.id, { write: true });
    if (!note) return page(res.status(404), 'Not found', req, '<h1>Note not found</h1>');
    db.prepare('DELETE FROM notes WHERE id = ?').run(note.id);
    res.redirect('/notes');
  });

  // FIX (lesson 7): the search term is a bound parameter; the sort column comes from an allowlist.
  const SORTS = { id: 'id', title: 'title' };
  function search(userId, q, sort = 'id') {
    if (!Object.hasOwn(SORTS, sort)) return undefined; // not SORTS[sort]: "constructor" would pass that check
    const column = SORTS[sort];
    const pattern = `%${String(q).replace(/[\\%_]/g, '\\$&')}%`; // % and _ in the term match literally
    // column is one of two fixed strings from SORTS, never request text, so this interpolation is safe.
    // nosemgrep: sql-built-with-template-literal
    return db.prepare(`SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ? ESCAPE '\\' ORDER BY ${column}`).all(userId, pattern);
  }
  app.get('/search', needLogin, (req, res) => {
    const q = String(req.query.q ?? '');
    page(res, 'Search', req, views.searchPage(q, q ? search(req.user.id, q) : []));
  });

  app.get('/profile', needLogin, (req, res) => page(res, 'Profile', req, views.profilePage(req.user, req.session.csrf)));
  app.post('/profile', needLogin, (req, res) => {
    db.prepare('UPDATE users SET display_name = ?, email = ? WHERE id = ?')
      .run(String(req.body.displayName ?? '').slice(0, 60), String(req.body.email ?? ''), req.user.id);
    res.redirect('/profile');
  });

  app.get('/admin', needLogin, needRole('admin'), (req, res) => {
    page(res, 'Admin', req, views.adminPage(db.prepare('SELECT id, email, role FROM users').all()));
  });

  // ---------- JSON API ----------
  const noteJson = (n) => ({ id: n.id, title: n.title, body: n.body });
  app.get('/api/me', needLogin, (req, res) => {
    const u = req.user;
    res.json({ id: u.id, email: u.email, displayName: u.display_name, role: u.role });
  });
  // FIX (lesson 15): limit must be a whole number from 1 to 50.
  app.get('/api/notes', needLogin, (req, res) => {
    const limit = Number(req.query.limit ?? 20);
    if (!Number.isInteger(limit) || limit < 1 || limit > 50) return res.status(400).json({ error: 'limit must be a whole number from 1 to 50' });
    res.json(db.prepare('SELECT * FROM notes WHERE owner_id = ? ORDER BY id LIMIT ?').all(req.user.id, limit).map(noteJson));
  });
  app.post('/api/notes', needLogin, (req, res) => {
    const { title, body = '' } = req.body ?? {};
    if (typeof title !== 'string' || !title || typeof body !== 'string') return res.status(400).json({ error: 'title is required' });
    const r = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)').run(req.user.id, title, body);
    res.status(201).json({ id: Number(r.lastInsertRowid), title, body });
  });
  app.get('/api/notes/search', needLogin, (req, res) => {
    const rows = search(req.user.id, req.query.q ?? '', req.query.sort ?? 'id');
    rows ? res.json(rows) : res.status(400).json({ error: 'sort must be one of: id, title' });
  });
  app.get('/api/notes/:id', needLogin, (req, res) => {
    const note = findNote(req.user, req.params.id);
    note ? res.json(noteJson(note)) : res.status(404).json({ error: 'Note not found' });
  });
  app.put('/api/notes/:id', needLogin, (req, res) => {
    const note = findNote(req.user, req.params.id, { write: true });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    const { title, body } = req.body ?? {};
    if (typeof title !== 'string' || !title || typeof body !== 'string') return res.status(400).json({ error: 'title and body are required' });
    db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?').run(title, body, note.id);
    res.json(noteJson({ ...note, title, body }));
  });
  app.delete('/api/notes/:id', needLogin, (req, res) => {
    const note = findNote(req.user, req.params.id, { write: true });
    if (!note) return res.status(404).json({ error: 'Note not found' });
    db.prepare('DELETE FROM notes WHERE id = ?').run(note.id);
    res.sendStatus(204);
  });

  // FIX (lessons 11 and 15): a public profile has two fields, nothing else.
  app.get('/api/users/:id', needLogin, (req, res) => {
    const user = db.prepare('SELECT id, display_name FROM users WHERE id = ?').get(req.params.id);
    user ? res.json({ id: user.id, displayName: user.display_name }) : res.status(404).json({ error: 'User not found' });
  });
  // FIX (lesson 15): only fields on the allowlist can be changed; anything else is a 400.
  const PROFILE_FIELDS = ['displayName', 'email'];
  app.patch('/api/profile', needLogin, (req, res) => {
    const body = req.body ?? {};
    const unknown = Object.keys(body).filter((k) => !PROFILE_FIELDS.includes(k));
    if (unknown.length) return res.status(400).json({ error: `These fields cannot be changed: ${unknown.join(', ')}` });
    const displayName = body.displayName ?? req.user.display_name;
    const email = body.email ?? req.user.email;
    if (typeof displayName !== 'string' || displayName.length < 1 || displayName.length > 60) return res.status(400).json({ error: 'displayName must be 1 to 60 characters' });
    if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(email)) return res.status(400).json({ error: 'email is not valid' });
    db.prepare('UPDATE users SET display_name = ?, email = ? WHERE id = ?').run(displayName, email, req.user.id);
    res.json({ id: req.user.id, email, displayName, role: req.user.role });
  });

  app.get('/api/admin/users', needLogin, needRole('admin'), (req, res) => {
    res.json(db.prepare('SELECT id, email, role FROM users').all());
  });

  // FIX (lesson 10): unknown routes and errors get a short, generic answer; the details go to the log.
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, req, res, next) => {
    const status = err.status >= 400 && err.status < 500 ? err.status : 500;
    log('[error]', { requestId: req.id, status, message: err.message, stack: err.stack });
    res.status(status).json({ error: status === 500 ? 'Something went wrong.' : 'Bad request.', requestId: req.id });
  });
  return app;
}
