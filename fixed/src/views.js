// HTML pages. Every value that came from a user goes through esc() before it reaches the HTML,
// every form carries the session's CSRF token, and there is no inline script (the CSP forbids it).
export const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

const csrfField = (token) => `<input type="hidden" name="_csrf" value="${esc(token)}">`;

export function layout(title, user, body, csrf) {
  const nav = user
    ? `<a href="/notes">Notes</a><a href="/search">Search</a><a href="/profile">Profile</a>
       ${user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
       <span class="who">Signed in as ${esc(user.display_name)}</span>
       <form method="post" action="/logout" class="inline">${csrfField(csrf)}<button>Log out</button></form>`
    : '<a href="/login">Log in</a>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)} - Pocket Notes</title>
<link rel="stylesheet" href="/static/style.css"></head><body><header><strong>Pocket Notes</strong>${nav}</header><main>${body}</main></body></html>`;
}

export const loginPage = (message = '') => `<h1>Log in</h1>
  ${message ? `<p class="error">${esc(message)}</p>` : ''}
  <form method="post" action="/login">
    <label>Email <input name="email" type="email"></label>
    <label>Password <input name="password" type="password"></label>
    <button>Log in</button>
  </form>`;

export const notesPage = (notes, csrf) => `<h1>Your notes</h1>
  <p id="filter" class="muted"></p>
  <ul>${notes.map((n) => `<li><a href="/notes/${n.id}">${esc(n.title)}</a></li>`).join('')}</ul>
  <h2>New note</h2>
  <form method="post" action="/notes">${csrfField(csrf)}
    <label>Title <input name="title"></label>
    <label>Body <textarea name="body" rows="3"></textarea></label>
    <button>Save</button>
  </form>
  <script src="/static/notes.js"></script>`;

export const notePage = (note, csrf) => `<h1>${esc(note.title)}</h1>
  <div class="body">${esc(note.body)}</div>
  <form method="post" action="/notes/${note.id}/delete">${csrfField(csrf)}<button>Delete note</button></form>`;

export const searchPage = (q, rows) => `<h1>Search</h1>
  <form method="get" action="/search"><input name="q" value="${esc(q)}"><button>Search</button></form>
  ${q ? `<p>Results for <b>${esc(q)}</b>: ${rows.length}</p>` : ''}
  <ul>${rows.map((n) => `<li><a href="/notes/${n.id}">${esc(n.title)}</a></li>`).join('')}</ul>`;

export const profilePage = (user, csrf) => `<h1>Your profile</h1>
  <form method="post" action="/profile">${csrfField(csrf)}
    <label>Display name <input name="displayName" value="${esc(user.display_name)}"></label>
    <label>Email <input name="email" value="${esc(user.email)}"></label>
    <button>Save profile</button>
  </form>`;

export const adminPage = (users) => `<h1>Admin: all users</h1>
  <ul>${users.map((u) => `<li>${u.id}. ${esc(u.email)} (${esc(u.role)})</li>`).join('')}</ul>`;
