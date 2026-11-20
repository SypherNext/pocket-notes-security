// Pocket Notes: a DELIBERATELY VULNERABLE practice app. Every "FLAW" comment marks a bug
// that one lesson of the course finds, proves and fixes. Never expose this app to a network.
import express from 'express';
import _ from 'lodash';
import { openDb, hashPassword } from './db.js';
import { config } from './config.js';
import * as views from './views.js';

export function createApp({ db = openDb(), log = console.log } = {}) {
  const app = express(); // FLAW (lesson 10): Express adds "X-Powered-By: Express" to every response
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  // ---------- sessions ----------
  // FLAW (lesson 5): session ids are a counter, so the next one is easy to guess.
  const sessions = new Map(); // sid -> { userId }
  let lastSid = 1000;
  const cookies = (req) =>
    Object.fromEntries((req.headers.cookie ?? '').split(';').filter((c) => c.includes('=')).map((c) => {
      const i = c.indexOf('=');
      return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
    }));

  app.use((req, res, next) => {
    let sid = cookies(req).sid;
    if (!sid || !sessions.has(sid)) {
      sid = String(++lastSid);
      sessions.set(sid, { userId: null });
      // FLAW (lesson 5): no HttpOnly, no SameSite, no Secure, no expiry.
      res.cookie('sid', sid);
    }
    req.sid = sid;
    req.session = sessions.get(sid);
    req.user = req.session.userId ? db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId) : null;
    next();
  });

  // FLAW (lesson 9): CORS reflects any Origin and allows cookies with it.
  app.use('/api', (req, res, next) => {
    if (req.headers.origin) {
      res.set('Access-Control-Allow-Origin', req.headers.origin);
      res.set('Access-Control-Allow-Credentials', 'true');
      res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
      res.set('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] ?? 'Content-Type');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  const needLogin = (req, res, next) => {
    if (!req.user) return req.path.startsWith('/api') || req.originalUrl.startsWith('/api') ? res.status(401).json({ error: 'Log in first' }) : res.redirect('/login');
    next();
  };
  const page = (res, title, user, body) => res.type('html').send(views.layout(title, user, body));

  // ---------- authentication ----------
  function login(email, password) {
    log('[login]', { email, password }); // FLAW (lesson 11): passwords written to the log
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email ?? '');
    // FLAW (lesson 4): two different messages tell an attacker which emails have accounts.
    if (!user) return { error: `No account found for ${email}` };
    if (user.password_hash !== hashPassword(password ?? '')) return { error: 'Wrong password' };
    return { user };
  }
  // FLAW (lesson 4): no limit on attempts, so a script can try thousands of passwords.
  // FLAW (lesson 5): the session id from before login is kept (session fixation).
  app.get('/login', (req, res) => page(res, 'Log in', null, views.loginPage()));
  app.post('/login', (req, res) => {
    const { user, error } = login(req.body.email, req.body.password);
    if (error) return page(res.status(401), 'Log in', null, views.loginPage(error));
    req.session.userId = user.id;
    res.redirect('/notes');
  });
  app.post('/api/login', (req, res) => {
    const { user, error } = login(req.body?.email, req.body?.password);
    if (error) return res.status(401).json({ error });
    req.session.userId = user.id;
    res.json({ id: user.id, email: user.email, displayName: user.display_name, role: user.role });
  });
  // FLAW (lesson 5): logout only asks the browser to forget the cookie; the session stays valid.
  app.post('/logout', (req, res) => res.clearCookie('sid').redirect('/login'));
  app.post('/api/logout', (req, res) => res.clearCookie('sid').json({ ok: true }));

  // FLAW (lesson 4): any password is accepted, even "1".
  app.post('/api/register', (req, res) => {
    const { email, password, displayName } = req.body ?? {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    const r = db.prepare('INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)')
      .run(email, displayName ?? email, hashPassword(password));
    log('[mail] welcome email via key', config.mailApiKey); // FLAW (lesson 11): secret in the log
    res.status(201).json({ id: Number(r.lastInsertRowid), email });
  });

  // ---------- notes (HTML) ----------
  app.get('/', (req, res) => res.redirect(req.user ? '/notes' : '/login'));
  app.get('/notes', needLogin, (req, res) => {
    const notes = db.prepare('SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id').all(req.user.id);
    page(res, 'Notes', req.user, views.notesPage(notes));
  });
  app.post('/notes', needLogin, (req, res) => {
    const r = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)').run(req.user.id, req.body.title, req.body.body ?? '');
    res.redirect(`/notes/${r.lastInsertRowid}`);
  });
  // FLAW (lesson 6): the note is loaded by id alone; whose it is never gets checked.
  app.get('/notes/:id', needLogin, (req, res) => {
    const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
    if (!note) return page(res.status(404), 'Not found', req.user, '<h1>Note not found</h1>');
    page(res, note.title, req.user, views.notePage(note));
  });
  // FLAW (lesson 9): a state-changing form with no CSRF token.
  app.post('/notes/:id/delete', needLogin, (req, res) => {
    db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
    res.redirect('/notes');
  });

  // FLAW (lesson 7): the search term is glued into the SQL text.
  function search(userId, q, sort = 'id') {
    return db.prepare(`SELECT id, title FROM notes WHERE owner_id = ${userId} AND title LIKE '%${q}%' ORDER BY ${sort}`).all();
  }
  app.get('/search', needLogin, (req, res) => {
    const q = req.query.q ?? '';
    page(res, 'Search', req.user, views.searchPage(q, q ? search(req.user.id, q) : []));
  });

  app.get('/profile', needLogin, (req, res) => page(res, 'Profile', req.user, views.profilePage(req.user)));
  app.post('/profile', needLogin, (req, res) => {
    db.prepare('UPDATE users SET display_name = ?, email = ? WHERE id = ?').run(req.body.displayName, req.body.email, req.user.id);
    res.redirect('/profile');
  });

  // FLAW (lesson 6): the admin page is only hidden from the menu; any logged-in user can open it.
  app.get('/admin', needLogin, (req, res) => {
    page(res, 'Admin', req.user, views.adminPage(db.prepare('SELECT id, email, role FROM users').all()));
  });

  // ---------- JSON API ----------
  app.get('/api/me', needLogin, (req, res) => {
    const u = req.user;
    res.json({ id: u.id, email: u.email, displayName: u.display_name, role: u.role });
  });
  // FLAW (lesson 15): no upper bound on limit.
  app.get('/api/notes', needLogin, (req, res) => {
    const limit = Number(req.query.limit ?? 20);
    res.json(db.prepare('SELECT * FROM notes WHERE owner_id = ? ORDER BY id LIMIT ?').all(req.user.id, limit));
  });
  app.post('/api/notes', needLogin, (req, res) => {
    const { title, body = '' } = req.body ?? {};
    if (!title) return res.status(400).json({ error: 'title is required' });
    const r = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)').run(req.user.id, title, body);
    res.status(201).json({ id: Number(r.lastInsertRowid), title, body });
  });
  app.get('/api/notes/search', needLogin, (req, res) => {
    res.json(search(req.user.id, req.query.q ?? '', req.query.sort));
  });
  // FLAW (lesson 6): IDOR on read, update and delete.
  app.get('/api/notes/:id', needLogin, (req, res) => {
    const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
    note ? res.json(note) : res.status(404).json({ error: 'Note not found' });
  });
  app.put('/api/notes/:id', needLogin, (req, res) => {
    db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?').run(req.body.title, req.body.body, req.params.id);
    res.json(db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id));
  });
  app.delete('/api/notes/:id', needLogin, (req, res) => {
    db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id);
    res.sendStatus(204);
  });

  // FLAW (lesson 11 and 15): returns every column, password hash included, for any user id.
  app.get('/api/users/:id', needLogin, (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    user ? res.json(user) : res.status(404).json({ error: 'User not found' });
  });
  // FLAW (lesson 15): mass assignment. Whatever the client sends is merged into the user, role included.
  app.patch('/api/profile', needLogin, (req, res) => {
    const updated = _.merge({}, req.user, req.body);
    db.prepare('UPDATE users SET display_name = ?, email = ?, role = ? WHERE id = ?')
      .run(updated.display_name, updated.email, updated.role, req.user.id);
    res.json(db.prepare('SELECT id, email, display_name, role FROM users WHERE id = ?').get(req.user.id));
  });

  // FLAW (lesson 6): no role check on the admin API.
  app.get('/api/admin/users', needLogin, (req, res) => {
    res.json(db.prepare('SELECT id, email, role FROM users').all());
  });
  // FLAW (lesson 11): anyone who has read the source code knows this token.
  app.post('/api/admin/reset-password', (req, res) => {
    if (req.body?.token !== config.adminResetToken) return res.status(403).json({ error: 'Bad token' });
    db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hashPassword(req.body.newPassword), req.body.email);
    res.json({ ok: true });
  });

  // FLAW (lesson 10): errors go back to the client with the stack trace and the SQL message.
  app.use((err, req, res, next) => {
    res.status(500).type('text').send(`Internal error\n${err.stack}`);
  });
  return app;
}
