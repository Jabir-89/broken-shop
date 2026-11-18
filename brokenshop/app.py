"""HTTP layer: routing, sessions, and the eight deliberately vulnerable handlers.

Run it:  python -m brokenshop [--port 8000]

Every view that carries a vulnerability is marked ``VULN(CHALLENGE n)`` so the
difference between the training app and a fixed version is a `grep` away.
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import socket
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import pages, security, store
from .bot import AdminBot

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
COOKIE = "sid"

CHALLENGE_LIST = [
    (1, "SQL injection", "POST /login"),
    (2, "Reflected + stored XSS", "GET /?q= and POST /reviews"),
    (3, "Path traversal", "GET /download?file="),
    (4, "JWT alg:none", "GET /api/admin"),
    (5, "SSRF", "GET /fetch?url="),
    (6, "CSRF (admin bot)", "POST /report + /admin/gift"),
    (7, "Race condition", "POST /redeem"),
    (8, "Mass assignment", "POST /account"),
]

ROUTES: list[tuple[str, str, str]] = [
    ("GET", r"/", "_home"),
    ("GET", r"/login", "_login_form"),
    ("POST", r"/login", "_login"),
    ("GET", r"/logout", "_logout"),
    ("GET", r"/account", "_account"),
    ("POST", r"/account", "_account_update"),
    ("GET", r"/orders/(\d+)", "_order"),
    ("POST", r"/buy", "_buy"),
    ("POST", r"/redeem", "_redeem"),
    ("GET", r"/reviews", "_reviews"),
    ("POST", r"/reviews", "_review_create"),
    ("GET", r"/admin", "_admin"),
    ("POST", r"/admin/gift", "_admin_gift"),
    ("GET", r"/api/token", "_api_token"),
    ("GET", r"/api/admin", "_api_admin"),
    ("GET", r"/fetch", "_fetch"),
    ("GET", r"/download", "_download"),
    ("GET", r"/internal/flag", "_internal_flag"),
    ("GET", r"/uploads/([A-Za-z0-9]+)\.html", "_serve_upload"),
    ("POST", r"/upload", "_upload"),
    ("POST", r"/report", "_report"),
    ("GET", r"/tools", "_tools"),
    ("GET", r"/challenges", "_challenges"),
]

COMPILED = [(m, re.compile(f"^{p}$"), name) for m, p, name in ROUTES]


class Handler(BaseHTTPRequestHandler):
    server_version = "broken-shop/1.0"
    protocol_version = "HTTP/1.0"

    # ---------------------------------------------------------------- plumbing

    @property
    def db(self):
        return self.server.db_path

    @property
    def fixes(self) -> bool:
        """True when the app runs with every vulnerability patched."""
        return bool(getattr(self.server, "fixes", False))

    def log_message(self, fmt: str, *args) -> None:  # quieter output
        if os.environ.get("BROKENSHOP_VERBOSE"):
            super().log_message(fmt, *args)

    def _query(self) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)

    def _path(self) -> str:
        return urllib.parse.urlsplit(self.path).path

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                return {k: str(v) for k, v in json.loads(raw or b"{}").items()}
            except json.JSONDecodeError:
                return {}
        parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    def _cookie_sid(self) -> str | None:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return None

    def _user(self):
        conn = store.connect(self.db)
        try:
            uid = security.session_user_id(conn, self._cookie_sid())
            return store.get_user(conn, uid) if uid else None
        finally:
            conn.close()

    def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8",
              headers: list[tuple[str, str]] | None = None) -> None:
        payload = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _page(self, title: str, body: str, status: int = 200,
              headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, pages.layout(title, body, self._user()), headers=headers)

    def _redirect(self, location: str, headers: list[tuple[str, str]] | None = None) -> None:
        self._send(303, "", headers=[("Location", location), *(headers or [])])

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload, indent=2), "application/json; charset=utf-8")

    def _dispatch(self, method: str) -> None:
        path = self._path()
        for verb, pattern, name in COMPILED:
            if verb != method:
                continue
            match = pattern.match(path)
            if match:
                getattr(self, name)(match)
                return
        # A known path with the wrong verb is 405, not 404 — clearer for learners
        # following the docs and skipping the "POST" part.
        for _verb, pattern, _name in COMPILED:
            if pattern.match(path):
                self._page("Method not allowed",
                           pages.simple("405", f"<p>{method} is not allowed on this path.</p>"), 405)
                return
        self._page("Not found", pages.simple("404", f"<p>No route for <code>{html.escape(path)}</code></p>"), 404)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    # ---------------------------------------------------------------- shop

    def _home(self, _match) -> None:
        q = self._query().get("q", [None])[0]
        if self.fixes and q is not None:
            q = html.escape(q)  # FIX(challenge 2): escape at the sink
        conn = store.connect(self.db)
        try:
            products = store.list_products(conn)
        finally:
            conn.close()
        self._page("Shop", pages.home(products, q))

    def _buy(self, _match) -> None:
        user = self._user()
        if not user:
            return self._redirect("/login")
        product_id = int(self._form().get("id", "0") or 0)
        conn = store.connect(self.db)
        try:
            product = store.get_product(conn, product_id)
            if not product:
                return self._page("Shop", pages.simple("Error", "<p>Unknown product.</p>"), 404)
            fresh = store.get_user(conn, user["id"])
            if fresh["coins"] < product["price"]:
                return self._page("Shop", pages.simple(
                    "Not enough coins",
                    f"<p>You have {fresh['coins']}, need {product['price']}.</p>"))
            with conn:
                conn.execute("UPDATE users SET coins = coins - ? WHERE id = ?",
                             (product["price"], user["id"]))
                cur = conn.execute("INSERT INTO orders (user_id, item, flag) VALUES (?,?,?)",
                                   (user["id"], product["name"], product["flag"]))
                order_id = cur.lastrowid
        finally:
            conn.close()
        self._redirect(f"/orders/{order_id}")

    def _redeem(self, _match) -> None:
        """VULN(CHALLENGE 7): check-then-act with no lock or atomic update."""
        user = self._user()
        if not user:
            return self._redirect("/login")
        conn = store.connect(self.db)
        try:
            if self.fixes:
                # FIX(challenge 7): check and write in one atomic statement
                with conn:
                    cur = conn.execute(
                        "UPDATE coupons SET used = 1 WHERE code = 'WELCOME' AND used = 0")
                if cur.rowcount != 1:
                    return self._page("Coupon", pages.simple("Coupon", "<p>Already redeemed.</p>"), 400)
                with conn:
                    conn.execute("UPDATE users SET coins = coins + 10 WHERE id = ?", (user["id"],))
                balance = store.get_user(conn, user["id"])["coins"]
                return self._page("Coupon", pages.simple("Coupon", f"<p>+10 coins. Balance: {balance}</p>"))
            coupon = conn.execute("SELECT * FROM coupons WHERE code = 'WELCOME'").fetchone()
            if not coupon or coupon["used"]:
                return self._page("Coupon", pages.simple("Coupon", "<p>Already redeemed.</p>"), 400)
            time.sleep(0.05)  # widens the window so parallel requests all pass the check
            with conn:
                conn.execute("UPDATE coupons SET used = 1 WHERE code = 'WELCOME'")
                conn.execute("UPDATE users SET coins = coins + ? WHERE id = ?",
                             (coupon["coins"], user["id"]))
            balance = store.get_user(conn, user["id"])["coins"]
        finally:
            conn.close()
        self._page("Coupon", pages.simple("Coupon", f"<p>+{coupon['coins']} coins. Balance: {balance}</p>"))

    def _order(self, match) -> None:
        """VULN(CHALLENGE 3): any logged-in user can read any order."""
        user = self._user()
        if not user:
            return self._redirect("/login")
        conn = store.connect(self.db)
        try:
            order = store.get_order(conn, int(match.group(1)))
            if self.fixes and order and order["user_id"] != user["id"]:
                order = None  # FIX(challenge 3): no cross-account reads
        finally:
            conn.close()
        if not order:
            return self._page("Order", pages.simple("Not found", "<p>No such order.</p>"), 404)
        self._page(f"Order #{order['id']}", pages.order_page(order, user))

    # ---------------------------------------------------------------- auth

    def _login_form(self, _match) -> None:
        self._page("Log in", pages.login_page())

    def _login(self, _match) -> None:
        """VULN(CHALLENGE 1): credentials interpolated into SQL."""
        form = self._form()
        username = form.get("username", "")
        password = form.get("password", "")
        conn = store.connect(self.db)
        try:
            if self.fixes:
                # FIX(challenge 1): parameters, never string interpolation
                row = conn.execute(
                    "SELECT * FROM users WHERE username = ? AND password = ?",
                    (username, password),
                ).fetchone()
            else:
                sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                row = conn.execute(sql).fetchone()
            if not row:
                return self._page("Log in", pages.login_page("Invalid credentials."), 401)
            sid = security.create_session(conn, row["id"])
        finally:
            conn.close()
        self._redirect("/", headers=[("Set-Cookie", f"{COOKIE}={sid}; Path=/; HttpOnly")])

    def _logout(self, _match) -> None:
        sid = self._cookie_sid()
        if sid:
            conn = store.connect(self.db)
            try:
                with conn:
                    conn.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
            finally:
                conn.close()
        self._redirect("/", headers=[("Set-Cookie", f"{COOKIE}=; Path=/; Max-Age=0")])

    def _account(self, _match) -> None:
        user = self._user()
        if not user:
            return self._redirect("/login")
        self._page("Account", pages.account_page(user))

    def _account_update(self, _match) -> None:
        """VULN(CHALLENGE 8): every submitted field is written to the user row."""
        user = self._user()
        if not user:
            return self._redirect("/login")
        form = self._form()
        # FIX(challenge 8): only fields a user may edit
        allowed = ("username", "note") if self.fixes else ("username", "note", "role", "coins")
        fields = {k: v for k, v in form.items() if k in allowed}
        if fields:
            assignments = ", ".join(f"{key} = ?" for key in fields)
            conn = store.connect(self.db)
            try:
                with conn:
                    conn.execute(f"UPDATE users SET {assignments} WHERE id = ?",
                                 (*fields.values(), user["id"]))
            finally:
                conn.close()
        self._redirect("/account")

    # ---------------------------------------------------------------- reviews

    def _reviews(self, _match) -> None:
        conn = store.connect(self.db)
        try:
            items = store.list_reviews(conn)
        finally:
            conn.close()
        self._page("Reviews", pages.reviews_page(items, self._user(), escape=self.fixes))

    def _review_create(self, _match) -> None:
        user = self._user()
        if not user:
            return self._redirect("/login")
        body = self._form().get("body", "").strip()
        if body:
            conn = store.connect(self.db)
            try:
                store.add_review(conn, user["username"], body)
            finally:
                conn.close()
        self._redirect("/reviews")

    # ---------------------------------------------------------------- admin

    def _admin(self, _match) -> None:
        user = self._user()
        if not user:
            return self._redirect("/login")
        if user["role"] != "admin":
            return self._page("Admin", pages.simple("Forbidden", "<p>Admins only.</p>"), 403)
        escalation = store.FLAGS["massassign"] if user["username"] != "admin" else None
        self._page("Admin", pages.admin_page(user, escalation))

    def _admin_gift(self, _match) -> None:
        """VULN(CHALLENGE 6): state-changing POST with no CSRF token."""
        user = self._user()
        if not user or user["role"] != "admin":
            return self._page("Admin", pages.simple("Forbidden", "<p>Admins only.</p>"), 403)
        if self.fixes:
            # FIX(challenge 6): a state change must come from our own page
            origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
            expected = f"http://{self.server.base_host}:{self.server.server_port}"
            if not origin.startswith(expected):
                return self._page("Admin", pages.simple("Rejected", "<p>Cross-site request refused.</p>"), 403)
        form = self._form()
        target = form.get("to", "")
        try:
            amount = int(form.get("amount", "0"))
        except ValueError:
            amount = 0
        amount = max(0, amount)  # a negative gift would drain coins
        conn = store.connect(self.db)
        try:
            with conn:
                conn.execute("UPDATE users SET coins = coins + ? WHERE username = ?", (amount, target))
        finally:
            conn.close()
        self._page("Admin", pages.simple(
            "Gift sent", f"<p>{amount} coins sent to <b>{html.escape(target)}</b>.</p>"))

    # ---------------------------------------------------------------- api

    def _api_token(self, _match) -> None:
        user = self._user()
        payload = {"sub": user["username"] if user else "guest",
                   "role": user["role"] if user else "user"}
        self._json({"token": security.jwt_encode(payload, store.JWT_SECRET)})

    def _api_admin(self, _match) -> None:
        """VULN(CHALLENGE 4): algorithm comes from the token header."""
        token = self._query().get("token", [None])[0]
        auth = self.headers.get("Authorization") or ""
        if not token and auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not token:
            return self._json({"error": "token required"}, 401)
        try:
            claims = security.jwt_decode(token, store.JWT_SECRET, allow_none=not self.fixes)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": str(exc)}, 401)
        if claims.get("role") != "admin":
            return self._json({"error": "admin role required", "claims": claims}, 403)
        self._json({"ok": True, "claims": claims, "flag": store.FLAGS["jwt"]})

    # ---------------------------------------------------------------- tools

    def _tools(self, _match) -> None:
        self._page("Tools", pages.tools_page())

    def _fetch(self, _match) -> None:
        """VULN(CHALLENGE 5): server-side request to any URL, no allowlist."""
        url = self._query().get("url", [""])[0]
        if not url:
            return self._page("Fetch", pages.simple("Fetch", "<p>Give a <code>url</code>.</p>"), 400)
        if not url.lower().startswith(("http://", "https://")):
            return self._page("Fetch", pages.simple("Fetch", "<p>Only http(s) URLs.</p>"), 400)
        if self.fixes:
            # FIX(challenge 5): refuse loopback / private / link-local destinations
            host = urllib.parse.urlsplit(url).hostname or ""
            try:
                address = ipaddress.ip_address(socket.gethostbyname(host))
            except (OSError, ValueError):
                return self._page("Fetch", pages.simple("Rejected", "<p>Host cannot be resolved.</p>"), 400)
            if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                return self._page("Fetch", pages.simple("Rejected", "<p>Internal addresses are not allowed.</p>"), 400)
        try:
            with urllib.request.urlopen(url, timeout=4) as response:  # noqa: S310 - intentional
                body = response.read(4000).decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return self._page("Fetch", pages.simple("Fetch failed", f"<pre>{html.escape(str(exc))}</pre>"))
        self._page("Fetch", pages.simple("Fetched", f"<pre>{html.escape(body)}</pre>"))

    def _download(self, _match) -> None:
        """VULN(CHALLENGE 3b): path joined without normalisation."""
        requested = self._query().get("file", ["receipt.txt"])[0]
        base = (DATA / "receipts").resolve()
        target = (base / requested).resolve()
        if self.fixes:
            # FIX(challenge 3b): the resolved path must stay inside receipts/
            try:
                target.relative_to(base)
            except ValueError:
                return self._page("Download", pages.simple("Rejected", "<p>Path outside the receipts folder.</p>"), 400)
        try:
            content = target.read_text(errors="replace")
        except OSError as exc:
            return self._page("Download", pages.simple("Error", f"<pre>{html.escape(str(exc))}</pre>"), 404)
        self._page("Download", pages.simple("File", f"<pre>{html.escape(content)}</pre>"))

    def _internal_flag(self, _match) -> None:
        client = self.client_address[0]
        if client not in ("127.0.0.1", "::1"):
            return self._page("Internal", pages.simple("Forbidden", "<p>Internal only.</p>"), 403)
        self._page("Internal", pages.simple("Internal endpoint", f'<p class="flag">{store.FLAGS["ssrf"]}</p>'))

    # ---------------------------------------------------------------- upload + bot

    def _serve_upload(self, match) -> None:
        name = match.group(1)
        path = DATA / "uploads" / f"{name}.html"
        if not path.is_file():
            return self._page("Not found", pages.simple("404", "<p>No such page.</p>"), 404)
        # Served raw on purpose: this is the victim's browser context.
        self._send(200, path.read_text(encoding="utf-8"))

    def _upload(self, _match) -> None:
        content = self._form().get("html", "")
        token = re.sub(r"[^a-z0-9]", "", (os.urandom(8).hex()))
        uploads = DATA / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        (uploads / f"{token}.html").write_text(content, encoding="utf-8")
        link = f"/uploads/{token}.html"
        self._page("Upload", pages.simple(
            "Uploaded",
            f'<p>Your page: <a id="upload-link" href="{link}">{link}</a></p>'
            f'<p class="muted">Send that path to the admin in Tools.</p>'))

    def _report(self, _match) -> None:
        target = self._form().get("url", "").strip()
        if not target:
            return self._page("Report", pages.simple("Report", "<p>No URL given.</p>"), 400)
        origin = f"http://{self.server.base_host}:{self.server.server_port}"
        if target.startswith("/"):
            target = origin + target
        # Safety rail: the bot only visits pages on this app. Without this the
        # /report endpoint would be an open SSRF proxy for any URL.
        if not target.startswith(origin + "/"):
            return self._page("Report", pages.simple(
                "Rejected", f"<p>The admin only reviews pages on this site ({html.escape(origin)}).</p>"), 400)
        bot = AdminBot(target_base=origin)
        log = bot.visit(target)
        self._page("Report", pages.simple("Admin bot report", f"<pre>{html.escape(log)}</pre>"))

    # ---------------------------------------------------------------- meta

    def _challenges(self, _match) -> None:
        self._page("Challenges", pages.challenges_page(CHALLENGE_LIST))




def create_server(host: str = "127.0.0.1", port: int = 8000, db_path: Path | None = None,
                  fixes: bool = False) -> ThreadingHTTPServer:
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "receipts").mkdir(exist_ok=True)
    (DATA / "secret").mkdir(exist_ok=True)
    (DATA / "uploads").mkdir(exist_ok=True)

    receipt = DATA / "receipts" / "receipt.txt"
    if not receipt.exists():
        receipt.write_text("Thanks for shopping at broken-shop.\nOrder #1 — Rubber Duck\n", encoding="utf-8")
    secret = DATA / "secret" / "flag.txt"
    if not secret.exists():
        secret.write_text(store.FLAGS["traversal"] + "\n", encoding="utf-8")

    db = db_path or (DATA / "shop.db")
    if not db.exists() or os.environ.get("BROKENSHOP_RESET"):
        store.init_db(db)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.db_path = db  # type: ignore[attr-defined]
    httpd.base_host = host  # type: ignore[attr-defined]
    httpd.fixes = fixes  # type: ignore[attr-defined]
    return httpd


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="brokenshop", description="Intentionally vulnerable shop (local lab only).")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=None)
    parser.add_argument("--fixes", action="store_true",
                        help="run with every vulnerability patched (defence mode)")
    args = parser.parse_args(argv)

    db_path = Path(args.db) if args.db else None
    httpd = create_server(args.host, args.port, db_path, fixes=args.fixes)
    url = f"http://{args.host}:{httpd.server_port}/"
    if args.fixes:
        print("broken-shop — FIXES MODE: every vulnerability patched.")
    else:
        print("broken-shop — intentionally vulnerable. Local use only.")
    print(f"  shop       {url}")
    print(f"  challenges {url}challenges")
    print(f"  solutions  {ROOT / 'docs' / 'SOLUTIONS.md'}")
    print("  Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
