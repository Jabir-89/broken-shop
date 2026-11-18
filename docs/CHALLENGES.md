# Challenges — hints

Try each one before opening the next column. Hints are ordered: nudge → strong
hint. Solutions with exact requests are in [SOLUTIONS.md](SOLUTIONS.md).

## 1. SQL injection — login bypass

| Level | Hint |
|---|---|
| Nudge | The login query is built by gluing your input into a string. |
| Strong | The password field is also inside the query. Can you make the database ignore the rest of the statement? |
| Think about | What does `--` mean in SQL? Why does the space after it matter? |

## 2. Reflected + stored XSS

| Level | Hint |
|---|---|
| Nudge | Search for a product, then look at the page source. |
| Strong | Reviews render the body with no escaping at all. Both `/` (search) and `/reviews` are sinks. |
| Think about | Escaping input on the way in, versus escaping on the way out. Which one actually stops XSS? |

> This one is browser-only: the flag is "your JavaScript ran", which the test
> suite cannot observe. Open DevTools → Console.

## 3. Path traversal — read outside the receipts folder

| Level | Hint |
|---|---|
| Nudge | `/download?file=receipt.txt` — do you control the whole filename? |
| Strong | The server joins your value onto `data/receipts/` and never normalises it. |
| Think about | Where does `..` take you, and what is one directory above `receipts`? |

## 4. JWT `alg:none` — forge an admin token

| Level | Hint |
|---|---|
| Nudge | `GET /api/token` gives you a signed token for your own user. Decode it — it is just base64. |
| Strong | The server reads the algorithm from the token header. What happens with `{"alg":"none"}` and an empty signature? |
| Think about | Why must a verifier pin the algorithm instead of trusting the token? |

## 5. SSRF — reach the internal endpoint

| Level | Hint |
|---|---|
| Nudge | `/fetch?url=` makes the *server* do the request. |
| Strong | `/internal/flag` refuses you — but who is "you" when the server calls it? |
| Think about | Which addresses should never be reachable from a user-supplied URL? |

## 6. CSRF — make the admin send you coins

| Level | Hint |
|---|---|
| Nudge | `/admin/gift` changes state with a POST that carries no CSRF token. |
| Strong | You can upload an HTML page, and an admin bot will visit it and submit any form it finds. The bot only visits pages on this app (safety rail), so upload your page to `/upload` first. |
| Think about | What does the browser send automatically that an attacker cannot read, but can cause? |

## 7. Race condition — redeem one coupon twice

| Level | Hint |
|---|---|
| Nudge | `/redeem` checks `used`, sleeps, then sets it. |
| Strong | Two requests that both read `used = 0` before either writes will both succeed. |
| Think about | Why is `UPDATE ... WHERE used = 0` safer than read-then-write? |

## 8. Mass assignment — make yourself admin

| Level | Hint |
|---|---|
| Nudge | The profile form updates the user row. Which fields does it accept? |
| Strong | `role` is in the allowlist. Add a hidden input, or just POST it with curl. |
| Think about | Why should the server decide which fields a user may change? |

---

## Running order, if you want a curriculum

1. **3, 5** — input reaches places it should not (traversal, SSRF)
2. **1** — input changes the query that runs (SQLi)
3. **8, 4** — input changes who you are (mass assignment, JWT)
4. **6, 7** — input sequences that break assumptions (CSRF, race)
5. **2** — output that becomes code (XSS)

That order goes from "server trusts input" to "server trusts sequence" to
"browser trusts output", which is roughly how the vulnerability classes build on
each other.
