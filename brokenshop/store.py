"""SQLite storage for broken-shop.

Every table and seed row here exists to make one vulnerability demonstrable.
Passwords are stored in plain text on purpose (see docs/CHALLENGES.md).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

FLAGS = {
    "sqli": "FLAG{sql1_byp4ss}",
    "idor": "FLAG{1d0r_0rd3r}",
    "traversal": "FLAG{tr4v3rs4l}",
    "jwt": "FLAG{jwt_n0n3_4lg}",
    "ssrf": "FLAG{ssrf_1nt3rn4l}",
    "csrf": "FLAG{csrf_b0t}",
    "race": "FLAG{r4c3_c0nd1t10n}",
    "massassign": "FLAG{m4ss_4ss1gnm3nt}",
}

JWT_SECRET = "secret1"  # VULN: deliberately weak, and 'none' is accepted
STARTING_COINS = 100

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user',
    note     TEXT,
    coins    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL,
    price INTEGER NOT NULL,
    flag  TEXT
);
CREATE TABLE IF NOT EXISTS orders (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item    TEXT NOT NULL,
    flag    TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    body     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coupons (
    code TEXT PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0,
    coins INTEGER NOT NULL DEFAULT 10
);
CREATE TABLE IF NOT EXISTS sessions (
    sid     TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created REAL NOT NULL
);
"""

SEED_USERS = [
    ("alice", "password123", "user", None, STARTING_COINS),
    ("bob", "hunter2", "user", None, STARTING_COINS),
    ("admin", "Adm1n!Shop", "admin", FLAGS["sqli"], 9999),
]

SEED_PRODUCTS = [
    ("Rubber Duck", 10, None),
    ("Golden Duck", 50, FLAGS["race"]),
    ("Platinum Duck", 1000, FLAGS["csrf"]),
]

SEED_ORDERS = [
    (1, "Rubber Duck", None),           # alice's order  -> /orders/1
    (3, "Platinum Duck (gift)", FLAGS["idor"]),  # admin's order -> /orders/2
]

SEED_REVIEWS = [
    ("alice", "Rubber duck arrived, 5 stars!"),
    ("admin", "Thanks for shopping. Admin inbox: check /admin"),
]


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    """Create the database and seed it if it is empty."""
    if db_path.exists():
        db_path.unlink()
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA)
        conn.executemany(
            "INSERT INTO users (username, password, role, note, coins) VALUES (?,?,?,?,?)",
            SEED_USERS,
        )
        conn.executemany("INSERT INTO products (name, price, flag) VALUES (?,?,?)", SEED_PRODUCTS)
        conn.executemany("INSERT INTO orders (user_id, item, flag) VALUES (?,?,?)", SEED_ORDERS)
        conn.executemany("INSERT INTO reviews (username, body) VALUES (?,?)", SEED_REVIEWS)
        conn.execute("INSERT INTO coupons (code, used, coins) VALUES ('WELCOME', 0, 10)")
    conn.close()


# --- small query helpers used by the views ------------------------------------

def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_products(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM products ORDER BY id").fetchall()


def get_product(conn: sqlite3.Connection, product_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()


def list_orders(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM orders WHERE user_id = ?", (user_id,)).fetchall()


def get_order(conn: sqlite3.Connection, order_id: int) -> sqlite3.Row | None:
    # VULN(IDOR): no owner check happens here or in the caller.
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


def add_review(conn: sqlite3.Connection, username: str, body: str) -> None:
    with conn:
        conn.execute("INSERT INTO reviews (username, body) VALUES (?,?)", (username, body))


def list_reviews(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM reviews ORDER BY id DESC").fetchall()
