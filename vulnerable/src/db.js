// SQLite in memory: every start (and every test) begins with the same seed data.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

// FLAW (lesson 11): unsalted SHA-256 is fast to guess and identical for identical passwords.
export const hashPassword = (password) => createHash('sha256').update(password).digest('hex');

export function openDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );
    CREATE TABLE notes (
      id INTEGER PRIMARY KEY,
      owner_id INTEGER NOT NULL REFERENCES users (id),
      title TEXT NOT NULL,
      body TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE shares (
      note_id INTEGER NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users (id),
      PRIMARY KEY (note_id, user_id)
    );
  `);
  const addUser = db.prepare('INSERT INTO users (email, display_name, password_hash, role) VALUES (?, ?, ?, ?)');
  addUser.run('admin@pocket.test', 'Ada Admin', hashPassword('Admin-Pocket-2026'), 'admin');
  addUser.run('alice@pocket.test', 'Alice', hashPassword('alice-likes-long-passwords'), 'user');
  addUser.run('bob@pocket.test', 'Bob', hashPassword('letmein'), 'user');
  const addNote = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)');
  addNote.run(1, 'Admin checklist', 'Rotate the mail API key in December.');
  addNote.run(2, 'Shopping list', 'Milk, eggs, coffee beans.');
  addNote.run(2, 'Salary review', 'Ask for 12 percent. Current offer from the other company: 98,000.');
  addNote.run(3, 'Gym plan', 'Monday legs, Wednesday back, Friday run 5 km.');
  db.prepare('INSERT INTO shares (note_id, user_id) VALUES (?, ?)').run(2, 3); // Alice shares her shopping list with Bob
  return db;
}
