"""A deliberately naive 'admin bot' used by the CSRF challenge.

It logs in as the admin, fetches a URL, and submits any form it finds — the
minimum needed to demonstrate that a state-changing request accepted without a
CSRF token can be triggered from another page. It does not execute JavaScript,
so it is a simulation of a browser, not a browser.
"""
from __future__ import annotations

import http.cookiejar
import re
import urllib.parse
import urllib.request

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
ATTR_RE = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")


def _attrs(raw: str) -> dict[str, str]:
    out = {}
    for match in ATTR_RE.finditer(raw):
        key = match.group(1).lower()
        value = next((v for v in match.groups()[1:] if v is not None), "")
        out[key] = value
    return out


def find_forms(page: str, base_url: str) -> list[tuple[str, dict[str, str]]]:
    """Return (absolute_action, form_data) for every POST form on the page."""
    forms = []
    for form_match in FORM_RE.finditer(page):
        attrs = _attrs(form_match.group(1))
        if attrs.get("method", "get").lower() != "post":
            continue
        action = urllib.parse.urljoin(base_url, attrs.get("action", base_url))
        data = {}
        for input_match in INPUT_RE.finditer(form_match.group(2)):
            fields = _attrs(input_match.group(1))
            name = fields.get("name")
            if name:
                data[name] = fields.get("value", "")
        forms.append((action, data))
    return forms


class AdminBot:
    def __init__(self, target_base: str, username: str = "admin",
                 password: str = "Adm1n!Shop", timeout: float = 5.0) -> None:
        self.base = target_base.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, url: str, data: dict[str, str] | None = None) -> str:
        payload = urllib.parse.urlencode(data).encode() if data is not None else None
        request = urllib.request.Request(url, data=payload)
        with self.opener.open(request, timeout=self.timeout) as response:
            return response.read().decode("utf-8", "replace")

    def visit(self, url: str) -> str:
        log: list[str] = []
        try:
            self._request(f"{self.base}/login", {"username": self.username, "password": self.password})
            log.append(f"bot: logged in as {self.username}")
        except Exception as exc:  # noqa: BLE001
            return f"bot: login failed: {exc}"

        try:
            page = self._request(url)
            log.append(f"bot: fetched {url} ({len(page)} bytes)")
        except Exception as exc:  # noqa: BLE001
            return "\n".join(log + [f"bot: fetch failed: {exc}"])

        for action, data in find_forms(page, url):
            try:
                self._request(action, data)
                log.append(f"bot: submitted form -> {action} {data}")
            except Exception as exc:  # noqa: BLE001
                log.append(f"bot: form failed -> {action}: {exc}")

        if len(log) == 2:
            log.append("bot: no POST forms found on that page")
        return "\n".join(log)
