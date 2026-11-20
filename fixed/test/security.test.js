// Security regression tests for Pocket Notes. Each test name starts with the lesson that
// adds it, so `node --test --test-name-pattern=L06` runs one lesson's tests.
// Against the vulnerable app almost every test fails; against the fixed app all pass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { createApp } from '../src/app.js';

const ALICE = { email: 'alice@pocket.test', password: 'alice-likes-long-passwords' };
const BOB = { email: 'bob@pocket.test', password: 'letmein' };

function start() {
  const logs = [];
  const app = createApp({ log: (...parts) => logs.push(parts.map((p) => (typeof p === 'string' ? p : JSON.stringify(p))).join(' ')) });
  return { app, logs };
}
const sidFrom = (res) => (res.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).find((c) => c.startsWith('sid='));

// Log in through the JSON API and return the "sid=..." cookie to send on later requests.
async function login(app, who) {
  const res = await request(app).post('/api/login').send(who);
  assert.equal(res.status, 200, `login as ${who.email} failed`);
  return sidFrom(res);
}

// ---------- lesson 4: authentication ----------
test('L04 login gives the same answer for an unknown email and a wrong password', async () => {
  const { app } = start();
  const unknown = await request(app).post('/api/login').send({ email: 'nobody@pocket.test', password: 'x' });
  const wrong = await request(app).post('/api/login').send({ email: BOB.email, password: 'x' });
  assert.equal(unknown.status, wrong.status);
  assert.deepEqual(unknown.body, wrong.body);
});

test('L04 login is rate limited after 5 failed attempts', async () => {
  const { app } = start();
  const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await request(app).post('/api/login').send({ email: BOB.email, password: `guess-${i}` })).status);
  assert.deepEqual(codes, [401, 401, 401, 401, 401, 429]);
});

test('L04 registration rejects short and common passwords', async () => {
  const { app } = start();
  for (const password of ['1', 'letmein', 'passwordpassword']) {
    const res = await request(app).post('/api/register').send({ email: `new-${password}@pocket.test`, password });
    assert.equal(res.status, 400, `"${password}" was accepted`);
  }
});

// ---------- lesson 5: sessions and cookies ----------
test('L05 session cookie is HttpOnly, SameSite and Secure', async () => {
  const { app } = start();
  const res = await request(app).post('/api/login').send(ALICE);
  const cookie = res.headers['set-cookie'].find((c) => c.startsWith('sid='));
  assert.match(cookie, /; HttpOnly/i);
  assert.match(cookie, /; SameSite=(Lax|Strict)/i);
  assert.match(cookie, /; Secure/i);
});

test('L05 session id is long and random', async () => {
  const { app } = start();
  const a = (await login(app, ALICE)).slice(4);
  const b = (await login(app, BOB)).slice(4);
  assert.ok(a.length >= 32, `session id "${a}" is too short`);
  assert.doesNotMatch(a, /^\d+$/, 'session id is only digits');
  assert.notEqual(Number(b) - Number(a), 1);
});

test('L05 session id changes at login', async () => {
  const { app } = start();
  const before = sidFrom(await request(app).get('/login')) ?? 'sid=planted-by-attacker';
  const res = await request(app).post('/api/login').set('Cookie', before).send(ALICE);
  const after = sidFrom(res);
  assert.ok(after, 'no new session cookie at login');
  assert.notEqual(after, before);
});

test('L05 logout ends the session on the server', async () => {
  const { app } = start();
  const sid = await login(app, ALICE);
  const out = await request(app).post('/api/logout').set('Cookie', sid).send({});
  assert.equal(out.status, 200);
  const res = await request(app).get('/api/notes').set('Cookie', sid);
  assert.equal(res.status, 401);
});

// ---------- lesson 6: access control ----------
test("L06 a user cannot read another user's note", async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).get('/api/notes/3').set('Cookie', bob); // note 3 is Alice's salary review
  assert.equal(res.status, 404);
  assert.equal((await request(app).get('/notes/3').set('Cookie', bob)).status, 404);
});

test("L06 a user cannot change or delete another user's note", async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  assert.equal((await request(app).put('/api/notes/3').set('Cookie', bob).send({ title: 'mine now', body: '' })).status, 404);
  assert.equal((await request(app).delete('/api/notes/3').set('Cookie', bob)).status, 404);
  const alice = await login(app, ALICE);
  assert.equal((await request(app).get('/api/notes/3').set('Cookie', alice)).body.title, 'Salary review');
});

test('L06 a shared note can be read but not deleted by the person it is shared with', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  assert.equal((await request(app).get('/api/notes/2').set('Cookie', bob)).status, 200);
  assert.equal((await request(app).delete('/api/notes/2').set('Cookie', bob)).status, 404);
});

test('L06 a non-admin gets 403 from the admin API and page', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  assert.equal((await request(app).get('/api/admin/users').set('Cookie', bob)).status, 403);
  assert.equal((await request(app).get('/admin').set('Cookie', bob)).status, 403);
});

// ---------- lesson 7: injection ----------
test('L07 search treats quotes as data, not SQL', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).get('/api/notes/search').query({ q: "' UNION SELECT id, email FROM users --" }).set('Cookie', bob);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, []);
});

test('L07 sort accepts only known columns', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  for (const sort of ['(SELECT password_hash FROM users)', 'constructor']) {
    const res = await request(app).get('/api/notes/search').query({ q: '', sort }).set('Cookie', bob);
    assert.equal(res.status, 400, `sort=${sort} gave ${res.status}`);
  }
});

// ---------- lesson 8: cross-site scripting ----------
test('L08 reflected search term is escaped', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).get('/search').query({ q: '<script>alert(1)</script>' }).set('Cookie', bob);
  assert.doesNotMatch(res.text, /<script>alert\(1\)<\/script>/);
  assert.match(res.text, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test('L08 stored note body is escaped', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const created = await request(app).post('/api/notes').set('Cookie', bob).set('Origin', 'http://localhost:18402')
    .send({ title: 'xss', body: '<img src=x onerror=alert(1)>' });
  const res = await request(app).get(`/notes/${created.body.id}`).set('Cookie', bob);
  assert.doesNotMatch(res.text, /<img src=x onerror=alert\(1\)>/);
  assert.match(res.text, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

// ---------- lesson 9: CSRF and CORS ----------
test('L09 a form post without a CSRF token is rejected', async () => {
  const { app } = start();
  const alice = await login(app, ALICE);
  const res = await request(app).post('/notes/2/delete').set('Cookie', alice).type('form').send({});
  assert.equal(res.status, 403);
});

test('L09 CORS does not trust an unknown origin', async () => {
  const { app } = start();
  const alice = await login(app, ALICE);
  const res = await request(app).get('/api/notes').set('Cookie', alice).set('Origin', 'http://evil.test');
  assert.equal(res.headers['access-control-allow-origin'], undefined);
});

// ---------- lesson 10: headers and errors ----------
test('L10 responses carry security headers', async () => {
  const { app } = start();
  const res = await request(app).get('/login');
  assert.match(res.headers['content-security-policy'] ?? '', /script-src 'self'/);
  assert.match(res.headers['content-security-policy'] ?? '', /frame-ancestors 'none'/);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-powered-by'], undefined);
});

test('L10 errors do not leak stack traces', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).get('/api/notes/search').query({ q: "'" }).set('Cookie', bob);
  assert.doesNotMatch(res.text, /at .*\.js:\d+/);
  assert.doesNotMatch(res.text, /SQL|sqlite/i);
});

// ---------- lesson 11: secrets and sensitive data ----------
test('L11 passwords never reach the log', async () => {
  const { app, logs } = start();
  await request(app).post('/api/login').send(ALICE);
  await request(app).post('/api/login').send({ email: BOB.email, password: 'wrong-guess' });
  assert.ok(logs.every((line) => !line.includes(ALICE.password) && !line.includes('wrong-guess')), logs.join('\n'));
});

test('L11 the user API does not return password hashes or emails', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).get('/api/users/2').set('Cookie', bob);
  assert.equal(res.status, 200);
  assert.deepEqual(Object.keys(res.body).sort(), ['displayName', 'id']);
});

// ---------- lesson 15: APIs ----------
test('L15 mass assignment cannot change role', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  const res = await request(app).patch('/api/profile').set('Cookie', bob).set('Origin', 'http://localhost:18402')
    .send({ displayName: 'Bobby', role: 'admin' });
  assert.ok(res.status === 200 || res.status === 400, `status ${res.status}`);
  const admin = await request(app).get('/api/admin/users').set('Cookie', bob);
  assert.equal(admin.status, 403);
});

test('L15 list limit is capped at 50', async () => {
  const { app } = start();
  const bob = await login(app, BOB);
  assert.equal((await request(app).get('/api/notes').query({ limit: 100000 }).set('Cookie', bob)).status, 400);
  assert.equal((await request(app).get('/api/notes').query({ limit: 50 }).set('Cookie', bob)).status, 200);
});
