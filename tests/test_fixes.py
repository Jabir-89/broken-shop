"""Tests for --fixes mode: every exploit from test_challenges must be blocked.

Same helpers as the vulnerable-mode suite, but the server runs with
``fixes=True`` so each handler takes its secure branch.
"""
from __future__ import annotations

import base64
import json
import re
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
ORIGIN_HEADER = "Origin"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Resp(NamedTuple):
    status: int
    body: str
    location: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class Client:
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

    def post(self, path: str, data: dict[str, str], headers: dict[str, str] | None = None) -> Resp:
        payload = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(self.base + path, data=payload, headers=headers or {})
        return self._do(request)


class FixedShopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SCRATCH.mkdir(exist_ok=True)
        cls.db = SCRATCH / f"fixed-{uuid.uuid4().hex[:8]}.db"
        cls.server = create_server("127.0.0.1", 0, cls.db, fixes=True)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.origin = cls.base
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

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
        self.assertEqual(response.status, 303, "legitimate login must still work")
        return browser

    # --- still works -------------------------------------------------------
    def test_normal_login_works(self):
        self.login("alice")

    def test_admin_login_works(self):
        browser = self.login("admin", "Adm1n!Shop")
        self.assertEqual(browser.get("/admin").status, 200)

    def test_buying_still_works(self):
        browser = self.login("alice")
        buy = browser.post("/buy", {"id": "1"})
        self.assertEqual(buy.status, 303)

    # --- exploits now fail -------------------------------------------------
    def test_sqli_blocked(self):
        response = Client(self.base).post("/login",
                                          {"username": "admin' -- ", "password": "x"})
        self.assertEqual(response.status, 401)

    def test_reflected_xss_escaped(self):
        body = Client(self.base).get("/?q=<script>alert(1)</script>").body
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_stored_xss_escaped(self):
        browser = self.login("bob", "hunter2")
        payload = "<img src=x onerror=alert(1)>"
        browser.post("/reviews", {"body": payload})
        page = browser.get("/reviews").body
        self.assertNotIn(payload, page)
        self.assertIn("&lt;img", page)

    def test_idor_blocked(self):
        self.assertEqual(self.login("alice").get("/orders/2").status, 404)

    def test_path_traversal_blocked(self):
        response = Client(self.base).get("/download?file=../secret/flag.txt")
        self.assertEqual(response.status, 400)
        self.assertNotIn(store.FLAGS["traversal"], response.body)

    def test_jwt_none_blocked(self):
        header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload = b64url(json.dumps({"sub": "x", "role": "admin"}).encode())
        token = f"{header}.{payload}."
        response = Client(self.base).get(f"/api/admin?token={urllib.parse.quote(token)}")
        self.assertEqual(response.status, 401)

    def test_ssrf_blocked(self):
        target = urllib.parse.quote(f"{self.base}/internal/flag", safe="")
        response = Client(self.base).get(f"/fetch?url={target}")
        self.assertEqual(response.status, 400)
        self.assertNotIn(store.FLAGS["ssrf"], response.body)

    def test_csrf_blocked(self):
        attacker = self.login("alice")
        before = re.search(r"coins: <b>(\d+)</b>", attacker.get("/account").body).group(1)
        page = (
            "<form action='/admin/gift' method='post'>"
            "<input name='to' value='alice'><input name='amount' value='1000'>"
            "</form>"
        )
        upload = attacker.post("/upload", {"html": page})
        path = upload.body.split('id="upload-link" href="')[1].split('"')[0]
        report = attacker.post("/report", {"url": path})
        self.assertEqual(report.status, 200)
        # The bot has no Origin header, so the gift must be refused.
        after = re.search(r"coins: <b>(\d+)</b>", attacker.get("/account").body).group(1)
        self.assertEqual(before, after, "balance must not change")

    def test_race_blocked(self):
        browser = self.login("bob", "hunter2")

        def redeem(_i: int) -> int:
            return browser.post("/redeem", {}).status

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(redeem, range(12)))

        self.assertEqual(sum(1 for s in statuses if s == 200), 1,
                         "exactly one redemption should succeed")
        self.assertIn("coins: <b>110</b>", browser.get("/account").body)

    def test_mass_assignment_blocked(self):
        browser = self.login("alice")
        browser.post("/account", {"role": "admin"})
        self.assertEqual(browser.get("/admin").status, 403)


if __name__ == "__main__":
    unittest.main()
