// Test file for taint-demo.yaml.
app.get('/a', (req, res) => {
  const q = req.query.q;
  // ruleid: request-data-into-sql-text
  res.json(db.prepare(`SELECT * FROM notes WHERE title LIKE '%${q}%'`).all());
});
app.get('/b', (req, res) => {
  // ok: request-data-into-sql-text
  res.json(db.prepare('SELECT * FROM notes WHERE title LIKE ?').all(`%${req.query.q}%`));
});
