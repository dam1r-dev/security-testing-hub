# Playbook: 15 attack classes — how to test and how to fix them

> ⚠️ **Authorized testing only.** Everything below is for checking **your
> own** application, or one you have explicit written permission to test
> (bug bounty scope, pentest engagement, CTF, a training lab like PortSwigger
> Web Security Academy or OWASP Juice Shop). Unauthorized access to systems
> you don't own or have permission to test is illegal in most jurisdictions.
> Test locally or in an isolated lab.

> 🇷🇺 Более подробная версия на русском: [attack-playbook.ru.md](attack-playbook.ru.md) · 🇰🇿 Қазақша: [attack-playbook.kk.md](attack-playbook.kk.md)

For each class: whether the scanner catches it automatically (and which
rule — see [docs/rules.md](rules.md)), how to check it by hand, and the fix.

## 1. Path Traversal

**CWE-22** · Auto-detected: ✅ `path-traversal`

**Test:** on a param that feeds a file path (`?filename=`, a route `:name`),
try `../../../etc/passwd` (or `..\..\..\windows\win.ini` on Windows). If the
server returns a system file's contents, it's exploitable.

**Fix:** never pass a client-supplied filename straight into `fs.*`; use an
allowlist of valid names, resolve the path and verify it stays inside the
intended base directory before touching the file.

## 2-3. Unprotected admin functionality (incl. hidden/unguessable URL)

**CWE-284 / CWE-862 (OWASP A01:2021)** · Auto-detected: ✅ `broken-access-control`

**Test:** look for hidden paths in `robots.txt`, HTML comments, the JS
bundle (`grep -r admin dist/`), sitemap.xml. Hit the path without (or with
a low-privilege) session and try a privileged action. If it works, access
isn't checked server-side — a secret URL is not access control.

**Fix:** check role/permissions on the server on every request to the
route, not just hide the link.

## 4. User role controlled by request parameter

**CWE-639 / CWE-807** · Auto-detected: ✅ `insecure-role-assignment`

**Test:** via a proxy, find a cookie/param like `role=user` or
`Admin=false`. Flip it to `Admin=true` / `role=admin` and replay the
request. If you gain admin-level access, the role isn't verified server-side.

**Fix:** store and check the role only server-side (session/DB by user id);
never trust a role value from the request.

## 5-6. IDOR (Insecure Direct Object Reference), incl. unpredictable IDs

**CWE-639** · Auto-detected: ✅ `idor`

**Test:** log in as two different test accounts. Swap the id in a request
from account A for account B's id (`/api/accounts/wiener` →
`/api/accounts/carlos`). If B's data comes back, ownership isn't checked.
For GUID-style ids, find another user's GUID elsewhere in the app (a
review, a public profile, a link) and substitute it — same underlying bug.

**Fix:** always check server-side that the requested object belongs to the
authenticated user (`WHERE owner_id = req.user.id`, not just `WHERE id = :id`).

## 7. IDOR with password disclosure

**CWE-639 + CWE-200** · Auto-detected: ⚠️ partial (`idor` catches the missing ownership check; the scanner can't see that a response body happens to include a password field)

**Test:** open another user's profile via IDOR (above), then inspect the
**raw** API response (Network tab / curl), not just the rendered page —
a `password`/`passwordHash` field can be present in the JSON even if the
UI masks it.

**Fix:** never include a password (even hashed) in an API response; check
object ownership as in 5-6.

## 8. Username enumeration via different responses

**CWE-203 / CWE-307** · Auto-detected: ⚠️ partial (`username-enumeration` only catches differing message text; status-code/timing differences need manual testing)

**Test:** with Burp Intruder (or a script), try a username list with a
wrong password. Compare error text, HTTP status, response length, and
**response time** (bcrypt.compare on a real user is usually slower than an
early return for a missing one). Any difference means enumeration is possible.

**Fix:** identical error message and status code for both cases
(`"Invalid username or password"`), constant-time handling (e.g. always run
`bcrypt.compare` against a dummy hash even when the user isn't found), rate
limiting and lockouts.

## 9. 2FA simple bypass

**CWE-287 / CWE-841** · Auto-detected: ❌ no (requires modeling session state/request flow — out of scope for AST-only static analysis)

**Test:** complete step one of login (username+password) but don't enter
the 2FA code. Instead, navigate directly to a URL that's only supposed to
be reachable after full login (`/my-account`). If it loads, 2FA is skippable.

**Fix:** the server must track "2FA not yet completed" as real session
state and block every protected endpoint until it's satisfied — the check
can't depend on which URL the client happens to request.

## 10-11. SSRF (local and against internal backend systems)

**CWE-918** · Auto-detected: ✅ `ssrf`

**Test:** find a param where the server itself fetches a URL (`stockApi`,
`webhookUrl`, a proxy/"impersonate" feature). Try `http://localhost/admin`
or `http://169.254.169.254/latest/meta-data/` (cloud metadata). For
internal networks, sweep a private range like `http://192.168.0.1-254:PORT/`.

**Fix:** allowlist permitted hosts/schemes; block loopback (127.0.0.1),
link-local (169.254.0.0/16) and private ranges (10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16); never accept a full URL from the client unvalidated.

## 12. Web shell upload via Content-Type restriction bypass

**CWE-434** · Auto-detected: ✅ `insecure-file-upload`

**Test:** prepare a minimal script (e.g. a trivial PHP file for a lab).
Upload it; in a proxy, change the multipart `Content-Type` from
`application/php` to `image/jpeg`. If it's accepted, try requesting the
uploaded file directly to see if it executes.

**Fix:** don't trust the client-supplied `Content-Type`; check the actual
file extension against an allowlist; store uploads outside the webroot (or
in object storage) and explicitly prevent execution.

## 13. OS Command Injection

**CWE-78** · Auto-detected: ✅ `command-injection`

**Test:** on a field that looks like it shells out (a host-check, file
conversion, ...), append `& whoami &` / `; whoami` / `` `whoami` ``
depending on context. If the command's output shows up in the response,
it's confirmed.

**Fix:** don't shell out with user data at all — use `execFile`/`spawn`
with an argv array (the shell never re-parses it); if a shell is
unavoidable, use a strict allowlist and proper escaping.

## 14. SQL Injection — retrieval of hidden data (WHERE clause)

**CWE-89** · Auto-detected: ✅ `sql-injection`

**Test:** on a param that feeds a query (category, search), try
`' OR 1=1--` or a `UNION SELECT` (matching column count). If records that
should be filtered out (unpublished items, other users' data) come back,
it's confirmed.

**Fix:** parameterized queries (prepared statements) only — never build SQL
by concatenating user input into it.

## 15. SQL Injection — login bypass

**CWE-89 / CWE-287** · Auto-detected: ✅ `sql-injection`

**Test:** in the username field, try `administrator'--`. If the query is
built by string concatenation, the password check gets commented out and
you're logged in without knowing the password.

**Fix:** parameterized queries (as in #14), plus proper password hashing
(bcrypt/argon2) — never plaintext or reversible encryption.

## Summary table

| # | Attack | Scanner rule | Coverage |
|---|---|---|---|
| 1 | Path Traversal | `path-traversal` | ✅ full |
| 2-3 | Unprotected admin | `broken-access-control` | ✅ full |
| 4 | Role from param | `insecure-role-assignment` | ✅ full |
| 5-6 | IDOR | `idor` | ✅ full |
| 7 | IDOR + password leak | `idor` | ⚠️ partial |
| 8 | Username enumeration | `username-enumeration` | ⚠️ partial |
| 9 | 2FA bypass | — | ❌ manual only |
| 10-11 | SSRF | `ssrf` | ✅ full |
| 12 | Web shell upload | `insecure-file-upload` | ✅ full |
| 13 | Command Injection | `command-injection` | ✅ full |
| 14-15 | SQL Injection | `sql-injection` | ✅ full |

See [docs/rules.md](rules.md) for exactly how (and where) each rule can be wrong.
