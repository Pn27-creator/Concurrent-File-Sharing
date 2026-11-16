"""Authentication: *who is this user?*

Users live in data/users.json.  Passwords are never stored; only a salted
PBKDF2-HMAC-SHA256 hash is.  (Authorization -- *what may this user do?* -- is
a separate question answered in metadata.py.)
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

ITERATIONS = 200_000
USERNAME_RE = re.compile(r"^[a-z0-9_-]{2,32}$")
ROLES = ("user", "admin")

# Brute-force protection: too many failures from one IP -> temporary lockout.
MAX_FAILURES = 5
FAILURE_WINDOW = 60      # seconds in which failures are counted
LOCKOUT_SECONDS = 30


def valid_username(name):
    return isinstance(name, str) and bool(USERNAME_RE.match(name))


def hash_password(password, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


# Used for unknown usernames so that "no such user" and "wrong password"
# take the same time (no username enumeration through timing).
_DUMMY_HASH = hash_password("dummy-password")


class UserStore:
    """Thread-safe view of users.json (re-read automatically when it changes)."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._mtime = None
        self._users = {}
        self._failures = {}   # ip -> [timestamps of recent failures]
        self._locked = {}     # ip -> unix time when the lockout ends
        self._reload()

    # -- storage ---------------------------------------------------------
    def _reload(self):
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            self._users, self._mtime = {}, None
            return
        if mtime != self._mtime:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._users = data.get("users", {})
            self._mtime = mtime

    def save(self, users):
        """Used by manage_users.py (offline admin tool)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"users": users}, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def all_users(self):
        with self._lock:
            self._reload()
            return json.loads(json.dumps(self._users))

    def exists(self, username):
        with self._lock:
            self._reload()
            return username in self._users

    def role(self, username):
        with self._lock:
            self._reload()
            return self._users.get(username, {}).get("role", "user")

    # -- login -----------------------------------------------------------
    def locked_for(self, ip):
        """Seconds left on this IP's lockout (0 if not locked)."""
        with self._lock:
            return max(0, int(self._locked.get(ip, 0) - time.time()))

    def check_login(self, ip, username, password):
        """Return (ok, role_or_error_message)."""
        remaining = self.locked_for(ip)
        if remaining:
            return False, f"Too many failed logins; try again in {remaining} s"

        with self._lock:
            self._reload()
            record = self._users.get(username) if isinstance(username, str) else None
        stored = record["password"] if record else _DUMMY_HASH
        good = verify_password(password if isinstance(password, str) else "", stored)

        with self._lock:
            if record and good:
                self._failures.pop(ip, None)
                return True, record.get("role", "user")
            now = time.time()
            recent = [t for t in self._failures.get(ip, []) if now - t < FAILURE_WINDOW]
            recent.append(now)
            self._failures[ip] = recent
            if len(recent) >= MAX_FAILURES:
                self._locked[ip] = now + LOCKOUT_SECONDS
                self._failures.pop(ip, None)
        return False, "Invalid username or password"
