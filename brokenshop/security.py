"""Sessions and tokens — both implemented insecurely on purpose.

* Sessions are a random id in a cookie, stored server-side. Fine by itself.
* JWTs are hand-rolled HS256 and accept ``alg: none`` (CHALLENGE 4).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# --- sessions -----------------------------------------------------------------

def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    sid = secrets.token_hex(16)
    with conn:
        conn.execute("INSERT INTO sessions (sid, user_id, created) VALUES (?,?,?)",
                     (sid, user_id, time.time()))
    return sid


def session_user_id(conn: sqlite3.Connection, sid: str | None) -> int | None:
    if not sid:
        return None
    row = conn.execute("SELECT user_id FROM sessions WHERE sid = ?", (sid,)).fetchone()
    return row["user_id"] if row else None


# --- tokens -------------------------------------------------------------------

def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps({**payload, "iat": int(time.time())},
                                    separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{head}.{body}.{b64url_encode(sig)}"


def jwt_decode(token: str, secret: str, allow_none: bool = True) -> dict:
    """Decode a token.

    VULN(CHALLENGE 4): the algorithm is taken from the *token header*, and
    ``alg: none`` is treated as "no signature needed". A real implementation
    pins the algorithm and always verifies.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    head, body, sig = parts
    header = json.loads(b64url_decode(head))
    alg = header.get("alg", "HS256")
    if alg == "none":
        if not allow_none:
            raise ValueError("alg:none is not accepted")
        return json.loads(b64url_decode(body))
    if alg != "HS256":
        raise ValueError(f"unsupported alg: {alg}")
    expected = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_decode(sig), expected):
        raise ValueError("bad signature")
    return json.loads(b64url_decode(body))
