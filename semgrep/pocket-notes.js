// Test file for pocket-notes.yaml: `semgrep --test` checks that each rule fires exactly
// on the lines marked "ruleid" and stays quiet on the lines marked "ok".

// ruleid: sql-built-with-template-literal
db.prepare(`SELECT * FROM notes WHERE title LIKE '%${q}%'`).all();
// ok: sql-built-with-template-literal
db.prepare('SELECT * FROM notes WHERE title LIKE ?').all(`%${q}%`);
// ok: sql-built-with-template-literal
db.prepare(`SELECT * FROM notes`).all();

const config = {
  // ruleid: hardcoded-secret-in-object
  mailApiKey: 'pn_live_8f3a9c2e71d04b6fa5e9c3d2b1a07f64',
  // ok: hardcoded-secret-in-object
  mailApiKeyName: process.env.MAIL_API_KEY,
  // ok: hardcoded-secret-in-object
  tokenHeader: 'Bearer',
};

// ruleid: password-in-log-call
log('[login]', { email, password });
// ruleid: password-in-log-call
console.log('signup', req.body);
// ok: password-in-log-call
log('[login]', { email, ok });
// ok: password-in-log-call
db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?').run(req.body.title, req.body.body, id);
// ok: password-in-log-call
const updated = _.merge({}, req.user, req.body);
