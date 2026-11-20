// HTML pages. FLAW (lesson 8): every value is pasted into the HTML as it is, never escaped.
const style = `
  body { font: 15px Segoe UI, Arial, sans-serif; margin: 0; color: #1a1a2e; background: #f7f8fb; }
  header { background: #1a1a2e; color: #fff; padding: 12px 24px; display: flex; gap: 18px; align-items: center; }
  header a { color: #cfe0fb; text-decoration: none; } header .who { margin-left: auto; color: #fff; }
  main { max-width: 760px; margin: 24px auto; background: #fff; padding: 20px 28px; border: 1px solid #d7dced; border-radius: 8px; }
  input, textarea { font: inherit; padding: 6px 8px; width: 100%; box-sizing: border-box; margin: 4px 0 12px; }
  button { font: inherit; padding: 6px 14px; background: #1a1a2e; color: #fff; border: 0; border-radius: 4px; }
  li { margin: 6px 0; } .error { color: #b94a4a; } .muted { color: #5b6478; }`;

export function layout(title, user, body) {
  const nav = user
    ? `<a href="/notes">Notes</a><a href="/search">Search</a><a href="/profile">Profile</a>
       ${user.role === 'admin' ? '<a href="/admin">Admin</a>' : ''}
       <span class="who">Signed in as ${user.display_name}</span>
       <form method="post" action="/logout" style="margin:0"><button>Log out</button></form>`
    : '<a href="/login">Log in</a>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${title} - Pocket Notes</title>
<style>${style}</style></head><body><header><strong>Pocket Notes</strong>${nav}</header><main>${body}</main></body></html>`;
}

export const loginPage = (message = '') => `<h1>Log in</h1>
  ${message ? `<p class="error">${message}</p>` : ''}
  <form method="post" action="/login">
    <label>Email <input name="email" type="email"></label>
    <label>Password <input name="password" type="password"></label>
    <button>Log in</button>
  </form>`;

export const notesPage = (notes) => `<h1>Your notes</h1>
  <p id="filter" class="muted"></p>
  <ul>${notes.map((n) => `<li><a href="/notes/${n.id}">${n.title}</a></li>`).join('')}</ul>
  <h2>New note</h2>
  <form method="post" action="/notes">
    <label>Title <input name="title"></label>
    <label>Body <textarea name="body" rows="3"></textarea></label>
    <button>Save</button>
  </form>
  <script>
    // FLAW (lesson 8, DOM XSS): the part of the URL after # goes straight into innerHTML.
    const tag = decodeURIComponent(location.hash.slice(1));
    if (tag) document.getElementById('filter').innerHTML = 'Showing notes tagged ' + tag;
  </script>`;

export const notePage = (note) => `<h1>${note.title}</h1>
  <div class="body">${note.body}</div>
  <form method="post" action="/notes/${note.id}/delete"><button>Delete note</button></form>`;

export const searchPage = (q, rows) => `<h1>Search</h1>
  <form method="get" action="/search"><input name="q" value="${q}"><button>Search</button></form>
  ${q ? `<p>Results for <b>${q}</b>: ${rows.length}</p>` : ''}
  <ul>${rows.map((n) => `<li><a href="/notes/${n.id}">${n.title}</a></li>`).join('')}</ul>`;

export const profilePage = (user) => `<h1>Your profile</h1>
  <form method="post" action="/profile">
    <label>Display name <input name="displayName" value="${user.display_name}"></label>
    <label>Email <input name="email" value="${user.email}"></label>
    <button>Save profile</button>
  </form>`;

export const adminPage = (users) => `<h1>Admin: all users</h1>
  <ul>${users.map((u) => `<li>${u.id}. ${u.email} (${u.role})</li>`).join('')}</ul>`;
