# ⚠️ WARNING — read before running

`broken-shop` contains **real, working vulnerabilities**. That is the point.
The danger is not hypothetical: an exposed instance can be used to run code on
your machine, read your files, or act as a foothold into your network.

## Rules

1. **Localhost only.** The app binds to `127.0.0.1` by default. Do not change
   that to `0.0.0.0` while you are learning.
2. **Do not expose it to the internet.** No port forwarding, no tunnels, no
   public VPS "just to show a friend".
3. **Never put real data in it.** Everything in the database is seed data; do
   not import anything real.
4. **Use a throwaway machine or container** if you want to experiment with
   anything beyond the built-in challenges — the SSRF and path-traversal
   endpoints can reach local files and services.
5. **Assume the flags you learn are disposable.** They are strings in source;
   they are not secrets.

## If you deploy it publicly anyway

You need, at minimum:

- an isolated network namespace or container with no host mounts
- no access to your home LAN, cloud metadata, or SSH keys
- a daily reset of the database and uploads directory
- a visible warning banner (already in the app) and a clear README

Even then, understand that anyone can use your instance to send requests from
*your* IP address. That is why the default is localhost.

## Legal note

Building and testing this kind of app against itself is normal security
education. Pointing these techniques at systems you do not own or administer is
a criminal offence in most countries — see the ethics section of the README.
