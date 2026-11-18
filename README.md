# broken-shop

An intentionally vulnerable web shop for learning web security — **8 planted
vulnerabilities, 8 flags, zero dependencies**.

Run it locally, break it, read why it broke.

```text
$ python -m brokenshop
broken-shop — intentionally vulnerable. Local use only.
  shop       http://127.0.0.1:8000/
  challenges http://127.0.0.1:8000/challenges
```

No pip install. No framework. Standard library only — it runs on any machine
with Python 3.9+, including one where `pip` is locked down.

> ⚠️ **This app is deliberately insecure.** It binds to `127.0.0.1` only and
> prints a warning banner. Read [WARNING.md](WARNING.md) before exposing it
> anywhere.

## Why another vulnerable app?

Juice Shop and DVWA are excellent, and they are also big. This one is ~950
lines of readable Python you can finish in an evening, where every vulnerability
is marked in the source with a `VULN(CHALLENGE n)` comment and every fix is
written out in [docs/FIXES.md](docs/FIXES.md).

It is built for the question: *"I can run the exploit — but why did the code
allow it?"*

## Quick start

```bash
git clone https://github.com/Jabir-89/broken-shop.git
cd broken-shop
python -m brokenshop
```

Open <http://127.0.0.1:8000>. Accounts:

| User | Password | Role |
|---|---|---|
| `alice` | `password123` | user |
| `bob` | `hunter2` | user |
| `admin` | `Adm1n!Shop` | admin |

Reset to a clean database anytime:

```bash
BROKENSHOP_RESET=1 python -m brokenshop     # Linux / macOS
$env:BROKENSHOP_RESET=1; python -m brokenshop   # PowerShell
```

### Docker (still localhost-only)

```bash
docker compose up --build
```

The compose file publishes the port as `127.0.0.1:8000:8000`, so it is not
reachable from your LAN.

## The challenges

| # | Class | Where | Flag |
|---|---|---|---|
| 1 | SQL injection | `POST /login` | login as admin without the password |
| 2 | Reflected + stored XSS | `GET /?q=` and `POST /reviews` | JavaScript of yours runs in the page |
| 3 | Path traversal | `GET /download?file=` | read `../secret/flag.txt` |
| 4 | JWT `alg:none` | `GET /api/admin` | forge an admin token |
| 5 | SSRF | `GET /fetch?url=` | reach the internal-only endpoint |
| 6 | CSRF | admin bot + `/admin/gift` | make the admin send you 1000 coins |
| 7 | Race condition | `POST /redeem` | spend one coupon more than once |
| 8 | Mass assignment | `POST /account` | give yourself the `admin` role |

Full walkthroughs with exact requests: [docs/SOLUTIONS.md](docs/SOLUTIONS.md).
Do yourself a favour and try each one first — the flags are in the app, not in
the docs.

## How it works

```text
brokenshop/
├── app.py        routing table, HTTP handlers, one VULN comment per flaw
├── store.py      SQLite schema + seed data + flags
├── pages.py      HTML templates (manual escaping, on purpose)
├── security.py   sessions and hand-rolled HS256 JWTs (accepts alg:none)
└── bot.py        naive admin bot that submits forms (simulates a browser)
```

Design notes:

- **Standard library HTTP server** (`ThreadingHTTPServer`) — threaded so the
  race-condition challenge is real, and no dependencies so anyone can run it.
- **SQLite in a file** — inspect it directly with `sqlite3 data/shop.db`.
- **Manual escaping** in `pages.py` — the XSS sinks are visible, not hidden
  behind a template engine that escapes by default.
- **The admin bot is a simulation**, not a browser: it fetches a URL and submits
  any POST form it finds. It never executes JavaScript, so challenge 2 is
  browser-only and is not auto-scored.

## Defence mode: --fixes

Run the same app with **every vulnerability patched**:

`ash
python -m brokenshop --fixes
`

Now try the attacks from [docs/SOLUTIONS.md](docs/SOLUTIONS.md):

| Attack | Result in fixes mode |
|---|---|
| dmin' --  login | rejected, no such user |
| <script> in search or reviews | escaped, shown as text |
| /orders/2 as alice | 404, not yours |
| ../secret/flag.txt | 400, outside the folder |
| lg:none token | 401, algorithm pinned |
| /fetch?url=http://127.0.0.1:... | 400, internal address blocked |
| admin bot submitting /admin/gift | 403, no matching Origin |
| 12 parallel coupon redemptions | exactly one succeeds |
| 
ole=admin in the profile form | ignored, field not allowed |

That contrast is the point: same app, same requests, different answers. The
code paths are marked FIX(challenge n) next to the VULN(challenge n) ones,
so grep -n VULN\|FIX brokenshop/app.py shows both sides together.

## Tests

```bash
python -m unittest discover -s tests -v
```

30 tests boot the real server: 17 exploit each challenge in vulnerable mode, 13 run the same attacks against --fixes and prove they fail — including
12 concurrent requests for the race condition. They are a regression suite *and*
a description of every vulnerability.

## Learning outcomes

After working through all eight you should be able to explain, without notes:

- why string-formatted SQL lets `' OR 1=1 --` through, and what a parameterised
  query changes
- why escaping at the sink is the control for XSS, not "sanitising input"
- why server-side authorization must check ownership, not just "logged in"
- why a JWT's `alg` header is attacker-controlled data
- why allowlisting beats blocklisting for SSRF targets
- why a state-changing request that works from another origin is a CSRF bug
- why "check then act" needs a lock or an atomic update
- why accepting arbitrary fields from a form is role escalation with extra steps

## Documentation

| File | Contents |
|---|---|
| [docs/CHALLENGES.md](docs/CHALLENGES.md) | Hints per challenge, graded from nudge to spoiler |
| [docs/SOLUTIONS.md](docs/SOLUTIONS.md) | Exact requests and expected flags |
| [docs/FIXES.md](docs/FIXES.md) | The secure version of each vulnerable line |
| [WARNING.md](WARNING.md) | Safety rules before running this |

## License

MIT — see [LICENSE](LICENSE).
