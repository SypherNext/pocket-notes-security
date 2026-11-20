// Look a leaked unsalted SHA-256 hash up against a small word list. Practice data only.
// Usage: node crack-sha256.mjs <hex-hash>
import { createHash } from 'node:crypto';

const target = process.argv[2];
const words = ['123456', 'password', 'qwerty', 'dragon', 'letmein', 'monkey', 'sunshine'];
const started = performance.now();
const hit = words.find((w) => createHash('sha256').update(w).digest('hex') === target);
console.log(hit ? `cracked: ${hit}` : 'not in the list', `(${(performance.now() - started).toFixed(2)} ms)`);
