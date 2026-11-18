"""HTML templates. Deliberately simple string formatting — no template engine.

Flask/Jinja would auto-escape; here escaping is manual, which is exactly why the
XSS challenges are possible. See docs/CHALLENGES.md.
"""
from __future__ import annotations

import html

CSS = """
* { box-sizing: border-box; }
body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
       background:#0f1117; color:#e6e8ee; line-height:1.5; }
a { color:#7db1ff; }
.wrap { max-width:900px; margin:0 auto; padding:0 20px 60px; }
nav { background:#171a23; border-bottom:1px solid #262b38; padding:12px 20px; }
nav .wrap { display:flex; gap:18px; align-items:center; padding:0; }
nav b { color:#fff; margin-right:8px; }
nav .spacer { flex:1; }
.banner { background:#3a1d1d; border-bottom:1px solid #6b2b2b; color:#ffb3b3;
          padding:10px 20px; font-size:14px; }
h1 { font-size:26px; margin:24px 0 8px; }
h2 { font-size:18px; margin:24px 0 8px; }
.card { background:#171a23; border:1px solid #262b38; border-radius:10px; padding:16px;
        margin:12px 0; }
.grid { display:grid; gap:12px; grid-template-columns:repeat(auto-fill, minmax(240px, 1fr)); }
.muted { color:#98a0b3; font-size:14px; }
code, pre { background:#0b0d13; border:1px solid #262b38; border-radius:6px;
            font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
code { padding:1px 5px; font-size:13px; }
pre { padding:12px; overflow:auto; font-size:13px; }
input, textarea, button { font:inherit; background:#0b0d13; color:#e6e8ee;
    border:1px solid #2d3342; border-radius:7px; padding:8px 10px; }
button { background:#2f6df6; border-color:#2f6df6; cursor:pointer; }
form { display:flex; gap:8px; flex-wrap:wrap; margin:8px 0; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:8px; border-bottom:1px solid #232838; }
.flag { color:#7bffab; font-family:ui-monospace, monospace; }
.badge { background:#24304a; color:#9fc0ff; border-radius:999px; padding:2px 10px; font-size:12px; }
"""

BANNER = ('<div class="banner">⚠️ Intentionally vulnerable training app — '
          'never expose this to the internet. Run it locally only.</div>')


def layout(title: str, body: str, user=None, extra_nav: str = "") -> str:
    who = ""
    if user:
        who = f'<span class="muted">{user["username"]} ({user["role"]}) · {user["coins"]} coins</span>'
    else:
        who = '<a href="/login">login</a>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · broken-shop</title><style>{CSS}</style></head>
<body>
{BANNER}
<nav><div class="wrap">
  <b>broken-shop</b>
  <a href="/">Shop</a>
  <a href="/reviews">Reviews</a>
  <a href="/account">Account</a>
  <a href="/challenges">Challenges</a>
  <a href="/tools">Tools</a>
  <span class="spacer"></span>
  {who}
</div></nav>
<div class="wrap">
<h1>{title}</h1>
{body}
</div>
</body></html>"""


def home(products, q: str | None) -> str:
    cards = "".join(
        f"""<div class="card"><b>{p['name']}</b>
        <div class="muted">{p['price']} coins</div>
        <form method="post" action="/buy">
          <input type="hidden" name="id" value="{p['id']}">
          <button>Buy</button>
        </form></div>""" for p in products
    )
    search = ""
    if q is not None:
        # VULN(CHALLENGE 2): user input echoed without escaping (reflected XSS)
        search = f'<div class="card">No results for <b>{q}</b></div>'
    return f"""
<form method="get" action="/">
  <input name="q" placeholder="search products" value="">
  <button>Search</button>
</form>
{search}
<h2>Products</h2>
<div class="grid">{cards}</div>
"""


def login_page(error: str = "") -> str:
    return f"""
{'<div class="card flag">' + error + '</div>' if error else ''}
<div class="card">
<form method="post" action="/login">
  <input name="username" placeholder="username" autofocus>
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form>
<p class="muted">Try: <code>alice</code> / <code>password123</code></p>
</div>
"""


def account_page(user) -> str:
    return f"""
<div class="card">
  <p>username: <b>{user['username']}</b></p>
  <p>role: <span class="badge">{user['role']}</span></p>
  <p>coins: <b>{user['coins']}</b></p>
  <p>note: {user['note'] or '<span class="muted">empty</span>'}</p>
</div>
<h2>Update profile</h2>
<div class="card">
<form method="post" action="/account">
  <input name="username" value="{user['username']}">
  <input name="note" placeholder="note" value="{user['note'] or ''}">
  <button>Save</button>
</form>
<p class="muted">The form posts every field it contains straight into the user row.</p>
</div>
"""


def order_page(order, user) -> str:
    flag = (f'<p class="flag">{order["flag"]}</p>' if order["flag"]
            else '<p class="muted">no flag in this order</p>')
    owner = "you" if user and order["user_id"] == user["id"] else f'user #{order["user_id"]}'
    return f"""
<div class="card">
  <p>order #{order['id']} — {order['item']}</p>
  <p class="muted">owner: {owner}</p>
  {flag}
</div>
"""


def reviews_page(reviews, user, escape: bool = False) -> str:
    def body(value: str) -> str:
        # VULN(CHALLENGE 2): renders raw. FIX: pass escape=True to escape at the sink.
        return html.escape(value) if escape else value

    items = "".join(
        f'<div class="card"><b>{html.escape(r["username"]) if escape else r["username"]}</b>'
        f'<div>{body(r["body"])}</div></div>'
        for r in reviews
    )
    form = ""
    if user:
        form = """<div class="card"><form method="post" action="/reviews">
          <input name="body" placeholder="your review" size="50">
          <button>Post</button></form></div>"""
    return f"{form}{items}"


def admin_page(user, escalation_flag: str | None) -> str:
    esc = ""
    if escalation_flag:
        esc = f'<div class="card"><b>escalation bonus</b><p class="flag">{escalation_flag}</p></div>'
    return f"""
<div class="card">
  <p>Signed in as <b>{user['username']}</b> with role <span class="badge">{user['role']}</span></p>
  <p>private note: <span class="flag">{user['note'] or 'none'}</span></p>
</div>
{esc}
<h2>Admin gift</h2>
<div class="card">
<form method="post" action="/admin/gift">
  <input name="to" placeholder="username">
  <input name="amount" placeholder="amount" value="1000">
  <button>Send coins</button>
</form>
<p class="muted">This form has no CSRF token — see challenge 6.</p>
</div>
"""


def tools_page() -> str:
    return """
<div class="card">
  <h2>Download a receipt</h2>
  <form method="get" action="/download">
    <input name="file" value="receipt.txt" size="40">
    <button>Download</button>
  </form>
</div>
<div class="card">
  <h2>Fetch a URL</h2>
  <form method="get" action="/fetch">
    <input name="url" placeholder="https://example.com" size="40">
    <button>Fetch</button>
  </form>
  <p class="muted">The server fetches whatever you give it — see challenge 5.</p>
</div>
<h2>Admin bot</h2>
<div class="card">
<form method="post" action="/report">
  <input name="url" placeholder="/uploads/abc.html" size="40">
  <button>Send to admin</button>
</form>
<p class="muted">The admin reviews any uploaded page. Upload one first (challenge 6).</p>
<div class="card">
<form method="post" action="/upload">
  <textarea name="html" rows="6" cols="60" placeholder="&lt;form action='/admin/gift' method='post'&gt;...&lt;/form&gt;"></textarea>
  <button>Upload HTML</button>
</form>
</div>
</div>
"""


def challenges_page(items) -> str:
    rows = "".join(
        f"<tr><td>{i}</td><td><b>{name}</b></td><td class='muted'>{where}</td></tr>"
        for i, name, where in items
    )
    return f"""
<div class="card">
<p class="muted">Eight vulnerabilities, eight flags. Each flag is worth finding once.
Full steps are in <code>docs/SOLUTIONS.md</code> — try first.</p>
<table><tr><th>#</th><th>Class</th><th>Where</th></tr>{rows}</table>
</div>
"""


def simple(title: str, body: str) -> str:
    return f'<div class="card">{body}</div>'
