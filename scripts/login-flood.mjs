// Send the same password to many different emails from one machine (password spraying shape).
// Usage: node login-flood.mjs <base-url> <count>
const [base, count = '60'] = process.argv.slice(2);
const tally = {};
for (let i = 0; i < Number(count); i++) {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `user${i}@pocket.test`, password: 'Summer2026' }),
  });
  tally[res.status] = (tally[res.status] ?? 0) + 1;
}
console.log(base, JSON.stringify(tally));
