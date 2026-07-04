"""Two-Factor Authentication (2FA) core logic.

This module implements a simple, self-contained two-factor authentication
system:

1. A user registers with a username and password (password is hashed).
2. On login, the user supplies the correct username/password (factor 1).
3. A one-time code (OTP) is generated, time-limited, and "delivered" to the
   user's registered email/mobile device (factor 2). In this demo, delivery
   is simulated by returning/printing the code instead of actually sending
   an email or SMS.
4. The user must submit the correct OTP within the validity window and
   before exceeding the maximum number of attempts to complete login.

The module is deliberately dependency-free (standard library only) so it is
easy to read, test, and reuse from a CLI or a web app.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

OTP_LENGTH = 6
OTP_VALIDITY_SECONDS = 300  # 5 minutes
MAX_OTP_ATTEMPTS = 5
PBKDF2_ITERATIONS = 200_000

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    """Raised for any authentication-flow error with a user-facing message."""


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return digest.hex()


def _generate_otp() -> str:
    """Generate a cryptographically-random numeric one-time code."""

    return "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))


@dataclass
class PendingChallenge:
    """A second-factor challenge awaiting verification."""

    username: str
    otp_hash: str
    salt: bytes
    created_at: float
    attempts: int = 0

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return (now - self.created_at) > OTP_VALIDITY_SECONDS


@dataclass
class User:
    username: str
    email: str
    password_hash: str
    salt: bytes


@dataclass
class TwoFactorAuthSystem:
    """In-memory two-factor authentication system.

    Swap the in-memory dicts for a real database in production; the
    algorithmic core (hashing, OTP generation/verification, rate limiting)
    stays the same.
    """

    users: Dict[str, User] = field(default_factory=dict)
    _pending: Dict[str, PendingChallenge] = field(default_factory=dict)
    _last_sent_otp: Dict[str, str] = field(default_factory=dict)  # demo/testing only

    # ---- Registration -------------------------------------------------

    def register(self, username: str, email: str, password: str) -> None:
        username = username.strip().lower()
        email = email.strip().lower()

        if not username:
            raise AuthError("Username is required.")
        if not EMAIL_PATTERN.match(email):
            raise AuthError("A valid email address is required.")
        if len(password) < 8:
            raise AuthError("Password must be at least 8 characters long.")
        if username in self.users:
            raise AuthError("That username is already registered.")

        salt = os.urandom(16)
        password_hash = _hash_password(password, salt)
        self.users[username] = User(
            username=username, email=email, password_hash=password_hash, salt=salt
        )

    # ---- Step 1: password check ---------------------------------------

    def login_step1(self, username: str, password: str) -> str:
        """Verify the password (factor 1) and issue an OTP (factor 2).

        Returns the OTP so the caller can "deliver" it (email/SMS/etc.).
        In a real system this method would send the OTP out-of-band and
        NOT return it to the caller.
        """

        username = username.strip().lower()
        user = self.users.get(username)

        # Constant-time-ish failure to avoid trivially leaking which part
        # (username vs password) was wrong.
        if user is None:
            raise AuthError("Invalid username or password.")

        candidate_hash = _hash_password(password, user.salt)
        if not hmac.compare_digest(candidate_hash, user.password_hash):
            raise AuthError("Invalid username or password.")

        otp = _generate_otp()
        otp_salt = os.urandom(16)
        otp_hash = _hash_password(otp, otp_salt)

        self._pending[username] = PendingChallenge(
            username=username, otp_hash=otp_hash, salt=otp_salt, created_at=time.time()
        )
        self._last_sent_otp[username] = otp  # demo-only convenience
        return otp

    # ---- Step 2: OTP check ---------------------------------------------

    def login_step2(self, username: str, otp: str) -> bool:
        """Verify the one-time code (factor 2). Returns True on success."""

        username = username.strip().lower()
        challenge = self._pending.get(username)

        if challenge is None:
            raise AuthError("No pending verification for this user. Please log in again.")

        if challenge.is_expired():
            del self._pending[username]
            raise AuthError("The verification code has expired. Please log in again.")

        if challenge.attempts >= MAX_OTP_ATTEMPTS:
            del self._pending[username]
            raise AuthError("Too many incorrect attempts. Please log in again.")

        candidate_hash = _hash_password(otp.strip(), challenge.salt)
        if not hmac.compare_digest(candidate_hash, challenge.otp_hash):
            challenge.attempts += 1
            remaining = MAX_OTP_ATTEMPTS - challenge.attempts
            if remaining <= 0:
                del self._pending[username]
                raise AuthError("Too many incorrect attempts. Please log in again.")
            raise AuthError(f"Incorrect code. {remaining} attempt(s) remaining.")

        # Success: consume the challenge so it cannot be reused (one-time).
        del self._pending[username]
        return True

    # ---- Helpers ---------------------------------------------------------

    def seconds_remaining(self, username: str) -> int:
        username = username.strip().lower()
        challenge = self._pending.get(username)
        if challenge is None:
            return 0
        remaining = OTP_VALIDITY_SECONDS - (time.time() - challenge.created_at)
        return max(0, int(remaining))

    def peek_last_otp(self, username: str) -> Optional[str]:
        """Demo helper only: reveals the last OTP issued for a user so this
        sample app can display it on-screen instead of wiring up real email
        or SMS delivery. A production system would never expose this.
        """

        return self._last_sent_otp.get(username.strip().lower())


def main() -> None:
    """Interactive CLI demo of the two-factor login flow."""

    system = TwoFactorAuthSystem()
    print("Two-Factor Authentication Demo")
    print("-" * 32)

    username = input("Choose a username: ")
    email = input("Email (for OTP delivery): ")
    password = input("Choose a password (min 8 chars): ")
    try:
        system.register(username, email, password)
    except AuthError as exc:
        print(f"Registration failed: {exc}")
        return

    print("\nRegistered! Now let's log in.\n")

    login_user = input("Username: ")
    login_pass = input("Password: ")
    try:
        otp = system.login_step1(login_user, login_pass)
    except AuthError as exc:
        print(f"Login failed: {exc}")
        return

    print(f"(Simulated email to {email}) Your one-time code is: {otp}")
    code = input("Enter the one-time code: ")
    try:
        system.login_step2(login_user, code)
        print("\n✅ Login successful — both factors verified.")
    except AuthError as exc:
        print(f"\n❌ Verification failed: {exc}")


if __name__ == "__main__":
    main()
