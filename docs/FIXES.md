# Fixes — the secure version of each flaw

Each section shows the vulnerable line from the source and the minimal fix, then
the invariant the fix restores. Every one of these fixes is already implemented:
run the app with --fixes to see them in action. These are the answers to "how would you fix it?"
in an interview.

## 1. SQL injection

```python
# vulnerable — brokenshop/app.py
sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
row = conn.execute(sql).fetchone()

# fixed — parameters, never interpolation
row = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
).fetchone()
```

**Invariant:** user input is *data*, never *syntax*. The driver sends the values
separately from the query text, so quotes cannot change the structure.

Also worth doing: store password hashes (`hashlib.scrypt`), never plaintext, and
compare with a constant-time function.

## 2. XSS

```python
# vulnerable — pages.py
f'<div class="card"><b>{r["username"]}</b><div>{r["body"]}</div></div>'

# fixed
f'<div class="card"><b>{html.escape(r["username"])}</b>'
f'<div>{html.escape(r["body"])}</div></div>'
```

**Invariant:** escape at the sink, in the context you are writing into (HTML
text vs attribute vs JavaScript string are different contexts). Input filtering
alone does not fix XSS, because the same value may be safe in one context and
dangerous in another.

Add defence in depth with a CSP header:

```python
self.send_header("Content-Security-Policy",
                 "default-src 'self'; script-src 'self'; object-src 'none'")
```

## 3. IDOR

```python
# vulnerable
order = store.get_order(conn, order_id)

# fixed — scope the query to the caller
order = conn.execute(
    "SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, user["id"])
).fetchone()
if order is None:
    return 404     # do not distinguish "not yours" from "does not exist"
```

**Invariant:** authorization is enforced in the query, not by hiding links. Also
return 404 rather than 403 for other users' objects, so ids are not enumerable.

## 3b. Path traversal

```python
# vulnerable
target = Path(os.path.join(base, requested))

# fixed — resolve, then prove the result is inside the base directory
base = (DATA / "receipts").resolve()
target = (base / requested).resolve()
if not target.is_relative_to(base):
    return 400
```

**Invariant:** after normalisation, the path must still be inside the allowed
directory. (`Path.is_relative_to` needs Python 3.9+; on older versions compare
`os.path.commonpath`.)

## 4. JWT algorithm confusion

```python
# vulnerable — security.py
alg = header.get("alg", "HS256")
if alg == "none":
    return json.loads(b64url_decode(body))

# fixed — pin the algorithm, always verify
if header.get("alg") != "HS256":
    raise ValueError("unexpected alg")
expected = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
if not hmac.compare_digest(b64url_decode(sig), expected):
    raise ValueError("bad signature")
```

**Invariant:** the verifier chooses the algorithm; the token only carries data.
Use a maintained library (`PyJWT` with `algorithms=["HS256"]`) rather than
hand-rolling, and never accept `none`.

## 5. SSRF

```python
# vulnerable
urllib.request.urlopen(url)

# fixed — allowlist scheme + host, resolve, block private ranges
parsed = urllib.parse.urlsplit(url)
if parsed.scheme not in ("http", "https"):
    return 400
if parsed.hostname not in ALLOWED_HOSTS:      # explicit allowlist
    return 400
ip = socket.gethostbyname(parsed.hostname)
if ipaddress.ip_address(ip).is_private:
    return 400
```

**Invariant:** the server must not be able to reach anything the user could not.
Allowlist beats blocklist, and disable redirects (`follow_redirects=False`),
because a public URL can redirect to `127.0.0.1`.

## 6. CSRF

```python
# vulnerable
def _admin_gift(self, _match):
    # state change driven by any cross-site POST

# fixed — token bound to the session, checked before acting
token = sessions.get(sid, {}).get("csrf")
if not hmac.compare_digest(form.get("csrf", ""), token):
    return 403
```

Plus cookie hardening:

```python
Set-Cookie: sid=...; Path=/; HttpOnly; Secure; SameSite=Lax
```

**Invariant:** a request from another origin cannot cause a state change. The
token proves the request came from your own page; `SameSite` adds a second layer.

## 7. Race condition

```python
# vulnerable
coupon = conn.execute("SELECT * FROM coupons WHERE code='WELCOME'").fetchone()
if coupon["used"]:
    return "already used"
time.sleep(0.05)
conn.execute("UPDATE coupons SET used = 1 ...")

# fixed — one atomic statement, check the row count
with conn:
    cur = conn.execute("UPDATE coupons SET used = 1 WHERE code = ? AND used = 0", ("WELCOME",))
if cur.rowcount != 1:
    return "already used"
conn.execute("UPDATE users SET coins = coins + ? WHERE id = ?", (coupon["coins"], user["id"]))
```

**Invariant:** the check and the write happen as one indivisible operation.
Alternatively wrap both statements in `BEGIN IMMEDIATE` so concurrent writers
serialise.

## 8. Mass assignment

```python
# vulnerable
allowed = ("username", "note", "role", "coins")
fields = {k: v for k, v in form.items() if k in allowed}

# fixed — allowlist only user-editable fields
EDITABLE = ("username", "note")
fields = {k: v for k, v in form.items() if k in EDITABLE}
```

**Invariant:** the server decides which fields a user may write. Privilege
fields (`role`), balances (`coins`) and identifiers are server-assigned only.
The same rule applies to JSON APIs: bind explicitly, never `**request.json`.

---

## Pattern behind all eight

Every vulnerability is the same mistake in a different costume: **the server
trusts something it did not verify**.

| Challenge | Trusted | Should have verified |
|---|---|---|
| SQLi | the string as query text | that input is data |
| XSS | the browser will not run it | that output is escaped for context |
| IDOR | the id belongs to you | ownership |
| Traversal | the path stays in the folder | normalised path prefix |
| JWT | the token's own header | signature with a pinned algorithm |
| SSRF | the URL points where it says | resolved destination |
| CSRF | the request came from your page | a session-bound token |
| Race | nothing changes between reads | atomicity |
| Mass assignment | the form only sends safe fields | which fields may be written |
