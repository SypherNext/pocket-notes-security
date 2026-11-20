// SQLite in memory: every start (and every test) begins with the same seed data.
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

// Passwords are stored with scrypt, a slow hash, and a random salt per user.
// (OWASP's Password Storage Cheat Sheet lists argon2id first and scrypt as an alternative;
// scrypt is built into Node, so the practice app needs no native module.)
const N = 2 ** 15; // cost: about 32 MiB of memory per hash
const opts = { N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32, opts);
  return `scrypt$${N}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifyPassword(password, stored) {
  const [, , salt, hash] = stored.split('$');
  const actual = scryptSync(password, Buffer.from(salt, 'base64url'), 32, opts);
  return timingSafeEqual(actual, Buffer.from(hash, 'base64url'));
}

// Used when the email is unknown, so a missing account costs the same time as a wrong password.
export const DUMMY_HASH = hashPassword('not-a-real-password');

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
  addUser.run('bob@pocket.test', 'Bob', hashPassword('letmein'), 'user'); // old weak password: the new rules apply to new passwords
  const addNote = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)');
  addNote.run(1, 'Admin checklist', 'Rotate the mail API key in December.');
  addNote.run(2, 'Shopping list', 'Milk, eggs, coffee beans.');
  addNote.run(2, 'Salary review', 'Ask for 12 percent. Current offer from the other company: 98,000.');
  addNote.run(3, 'Gym plan', 'Monday legs, Wednesday back, Friday run 5 km.');
  db.prepare('INSERT INTO shares (note_id, user_id) VALUES (?, ?)').run(2, 3); // Alice shares her shopping list with Bob
  return db;
}
