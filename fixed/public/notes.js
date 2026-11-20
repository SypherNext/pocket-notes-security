// The DOM XSS fix: textContent treats the value as text, never as HTML.
const tag = decodeURIComponent(location.hash.slice(1));
if (tag) document.getElementById('filter').textContent = 'Showing notes tagged ' + tag;
