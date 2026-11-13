"""
SEC-03 before/after evidence: repeated failed logins against YOUR LOCAL demo server.

It sends N wrong passwords, then the correct password, and prints the HTTP
result of each attempt.

  Before the fix: the correct password still logs in (302) -> no rate limit.
  After the fix:  the correct password is refused with 429 -> rate limit works.

Usage (server must be running: uv run python manage.py runserver 127.0.0.1:8080)
    uv run python security-tests/sec03_login_bruteforce_check.py --username support_agent
    uv run python security-tests/sec03_login_bruteforce_check.py --username admin --mode api

The correct password is asked for with a hidden prompt, so it is not saved in
your terminal history. Only use a local test account.
"""

import argparse
import getpass
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
TOKEN_RE = re.compile(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)')


def web_attempt(session, base_url, username, password):
    """Log in through the HTML form, like a browser (CSRF token included)."""
    login_url = f"{base_url}/login/"
    page = session.get(login_url, timeout=10)
    match = TOKEN_RE.search(page.text)
    data = {"username": username, "password": password}
    if match:
        data["csrfmiddlewaretoken"] = match.group(1)
    response = session.post(
        login_url,
        data=data,
        headers={"Referer": login_url},
        allow_redirects=False,
        timeout=10,
    )
    return response


def api_attempt(session, base_url, username, password):
    """Authenticate to the REST API with HTTP Basic (no CSRF token needed)."""
    return session.get(
        f"{base_url}/api/tickets/",
        auth=(username, password),
        allow_redirects=False,
        timeout=10,
    )


def describe(response, mode):
    code = response.status_code
    if code == 429:
        return f"BLOCKED (Retry-After: {response.headers.get('Retry-After')}s)"
    if mode == "web":
        return "LOGGED IN" if code == 302 else "login failed"
    if code == 200:
        return "AUTHENTICATED"
    # DRF returns 401 or 403 for a wrong password (403 here because
    # SessionAuthentication is its first authentication class), so read the message
    try:
        detail = str(response.json().get("detail", ""))
    except ValueError:
        detail = ""
    if code in (401, 403) and ("Invalid username/password" in detail or code == 401):
        return "auth failed (wrong password)"
    if code == 403:
        return f"authenticated but not permitted: {detail}"
    return f"auth failed: {detail}"


def main():
    parser = argparse.ArgumentParser(
        description="SEC-03 login rate-limit check (local only)"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--attempts", type=int, default=5, help="number of wrong passwords"
    )
    parser.add_argument("--mode", choices=["web", "api"], default="web")
    args = parser.parse_args()

    host = urlparse(args.base_url).hostname
    if host not in ALLOWED_HOSTS:
        sys.exit(
            f"Refusing to run against {host}: this script is for the local demo only."
        )

    correct = getpass.getpass(
        f"Correct password for local test user '{args.username}': "
    )
    attempt = web_attempt if args.mode == "web" else api_attempt
    session = requests.Session()

    print(
        f"\nSEC-03 check  mode={args.mode}  target={args.base_url}  user={args.username}"
    )
    print(f"{'#':>2}  {'time':8}  {'password':9}  {'HTTP':4}  result")
    print("-" * 60)

    for i in range(1, args.attempts + 1):
        response = attempt(session, args.base_url, args.username, f"wrong-guess-{i}")
        print(
            f"{i:>2}  {datetime.now():%H:%M:%S}  {'wrong':9}  {response.status_code:<4}  "
            f"{describe(response, args.mode)}"
        )
        time.sleep(0.2)

    response = attempt(session, args.base_url, args.username, correct)
    print(
        f"{args.attempts + 1:>2}  {datetime.now():%H:%M:%S}  {'CORRECT':9}  "
        f"{response.status_code:<4}  {describe(response, args.mode)}"
    )
    print("-" * 60)

    if response.status_code == 429:
        print(
            "RESULT: correct password refused after repeated failures -> rate limiting is ACTIVE."
        )
    elif response.status_code in (200, 302):
        print(
            "RESULT: correct password accepted right after the failures -> NO rate limiting."
        )
    else:
        print(
            f"RESULT: unexpected status {response.status_code}; check the server output."
        )


if __name__ == "__main__":
    main()
