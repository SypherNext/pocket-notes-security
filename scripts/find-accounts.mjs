// Ask the login endpoint about each email and sort the answers. Practice app only.
// Usage: node find-accounts.mjs <base-url>
const [base = 'http://127.0.0.1:18401'] = process.argv.slice(2);
const emails = ['admin@pocket.test', 'root@pocket.test', 'alice@pocket.test', 'carol@pocket.test', 'bob@pocket.test', 'support@pocket.test'];
for (const email of emails) {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'not-the-password' }),
  });
  const { error } = await res.json();
  console.log(`${email.padEnd(22)} ${res.status}  ${error}`);
}
