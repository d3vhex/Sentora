"""A second factor for operator logins.

The console has been protected by one password and a lockout. That is enough
against guessing and nothing at all against a password that has been reused,
phished, or read out of somebody's browser - and this console can isolate a
host, run a command as SYSTEM on every endpoint, and read every log the fleet
has produced.

What this module is careful about, in the order the mistakes usually happen:

**The pending state is not a session.** Passing the password gets a short-lived
token that can do exactly one thing: present a second factor. Issuing a real
session and "upgrading" it later means a window in which one factor is a
logged-in operator, and every bug in that window is a bypass.

**A code may be used once.** TOTP is a shared secret and a clock, so the same
six digits are valid for the whole step. Without a replay guard, anyone who
watches one code being typed has thirty seconds to use it themselves - which
is exactly the position a shoulder-surfer or a proxy is in.

**Recovery codes are credentials.** They are stored the way passwords are, as
hashes, and burnt on use. Storing them in the clear so the console can show
them again is the same mistake as storing a password, made for a friendlier
reason.

**The secret is encrypted at rest.** A TOTP secret is enough to mint codes for
ever. The server already holds a Fernet key for telemetry; the seed goes
through it, so a dump of `userdb` alone does not hand over everybody's second
factor.

**Enrolment is not complete until a code is proved.** A secret written at the
moment the QR code is shown, with no confirmation, locks out every operator
who scans it into an app they then delete. Nothing is enforced until one code
from the new secret has been verified.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time

#: Seconds per code. The interoperable value - every authenticator app assumes
#: it, and it is not worth being unusual about.
STEP_SECONDS = 30

#: How many steps either side of now are accepted.
#:
#: One. That is 30 seconds of clock skew in each direction, which covers a
#: phone that has not synchronised recently without widening the window an
#: attacker gets to reuse an observed code. Zero would reject honest users on
#: ordinary drift; three is 90 seconds of replay surface for no gain.
ALLOWED_DRIFT_STEPS = 1

#: Digits in a code. Six, for the same reason as the step: universal.
DIGITS = 6

#: Recovery codes issued when the second factor is enabled.
#:
#: Ten is enough to survive losing a phone more than once without becoming a
#: list somebody prints and leaves on a desk.
RECOVERY_CODE_COUNT = 10

#: Bytes of entropy per recovery code. 20 hex characters at 80 bits - long
#: enough that guessing is not a strategy, short enough to type from paper.
RECOVERY_CODE_BYTES = 10


def new_secret() -> str:
    """A fresh base32 seed, in the shape every authenticator app expects.

    160 bits, per RFC 4226's recommendation for HMAC-SHA1. `secrets` rather
    than `random`: this is key material.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    """One HOTP value, which is all TOTP is with the counter set from a clock.

    Written out rather than pulled in. It is eleven lines of RFC 4226, it has
    no dependency worth adding for, and the padding rule below is the kind of
    detail a comment can carry and a library cannot.
    """
    # Authenticator apps hand out secrets with the `=` padding stripped;
    # `b32decode` insists on it. Restoring it here means a user pasting a
    # secret from anywhere works.
    padded = secret_b32.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    key = base64.b32decode(padded, casefold=True)

    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def current_step(at: float | None = None) -> int:
    """Which time step we are in. Exposed so the replay guard can name one."""
    return int((time.time() if at is None else at) // STEP_SECONDS)


def codes_in_window(secret_b32: str, at: float | None = None) -> dict[int, str]:
    """{step: code} for every step currently acceptable.

    Returns the steps as well as the codes because the caller has to record
    *which* step it accepted - see the replay guard. A function that returned
    only a boolean would make single-use impossible to implement.
    """
    now = current_step(at)
    return {step: _hotp(secret_b32, step)
            for step in range(now - ALLOWED_DRIFT_STEPS,
                              now + ALLOWED_DRIFT_STEPS + 1)}


def verify(secret_b32: str, code: str, at: float | None = None) -> int | None:
    """The step a code is valid for, or None.

    Compared with `compare_digest`. A plain `==` on a six-digit code leaks how
    much of it was right through timing, and six digits is a small enough
    space that it is worth not helping.
    """
    cleaned = (code or "").strip().replace(" ", "").replace("-", "")

    # ASCII digits specifically, not `isdigit()`.
    #
    # `"٠١٢٣٤٥".isdigit()` is True - those are
    # Arabic-Indic digits, and Python counts every decimal digit in Unicode.
    # Six of them pass a length check and reach `compare_digest`, which raises
    # `TypeError: comparing strings with non-ASCII characters is not
    # supported`. So a login form that accepted any non-Latin numeral turned a
    # typo into a 500 on the authentication path.
    if len(cleaned) != DIGITS or not all(c in "0123456789" for c in cleaned):
        return None
    for step, expected in codes_in_window(secret_b32, at).items():
        if hmac.compare_digest(cleaned, expected):
            return step
    return None


def provisioning_uri(secret_b32: str, *, account: str, issuer: str) -> str:
    """The `otpauth://` URI an authenticator app scans.

    Assembled rather than formatted with the secret interpolated raw: an
    account name is a username and usernames contain characters that would
    otherwise end the query string early.
    """
    from urllib.parse import quote, urlencode

    label = quote(f"{issuer}:{account}", safe="")
    params = urlencode({
        "secret": secret_b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": STEP_SECONDS,
    })
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Codes to show once and never again.

    Grouped with a dash purely so they can be read aloud and typed from paper
    without losing your place; `verify_recovery` strips it back out.
    """
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(RECOVERY_CODE_BYTES)
        codes.append(f"{raw[:10]}-{raw[10:]}")
    return codes


def hash_recovery(code: str) -> str:
    """How a recovery code is stored. Never the code itself.

    SHA-256 and not bcrypt, deliberately, and the reasoning matters because
    the opposite is right for passwords: these are 80 bits of machine-chosen
    entropy, so there is no dictionary to slow down and nothing to stretch. A
    cost factor here would only make the login path slower.
    """
    cleaned = (code or "").strip().replace("-", "").replace(" ", "").lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

DDL_SECRETS = """
CREATE TABLE IF NOT EXISTS user_totp (
    user_id      INT NOT NULL PRIMARY KEY,
    secret       VARCHAR(512) NOT NULL,
    confirmed_at TIMESTAMP NULL DEFAULT NULL,
    created_at   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    last_step    BIGINT UNSIGNED NULL,
    CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

# `secret` is VARCHAR(512) rather than the ~32 characters a base32 seed needs,
# because it is stored encrypted and Fernet ciphertext is a hundred-odd
# characters regardless of the plaintext. Sizing a column for the value a
# human would read is how `network_connections` lost a day of telemetry to
# "Data too long" on this codebase already.

DDL_RECOVERY = """
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    code_hash  CHAR(64) NOT NULL,
    used_at    TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_recovery (user_id, code_hash),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

#: How long a half-authenticated login may sit before the password has to be
#: presented again.
#:
#: Five minutes: long enough to find a phone, short enough that a token left
#: in a URL bar or a proxy log is not a standing invitation.
PENDING_TTL_SECONDS = 300

DDL_PENDING = """
CREATE TABLE IF NOT EXISTS totp_pending (
    token_hash CHAR(64) NOT NULL PRIMARY KEY,
    user_id    INT NOT NULL,
    username   VARCHAR(50) NOT NULL,
    auth_type  VARCHAR(16) NOT NULL,
    ip         VARCHAR(64) NULL,
    attempts   INT UNSIGNED NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_pending_expiry (expires_at),
    CONSTRAINT fk_pending_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

# Stored as a hash, like a session token, and for the same reason: a dump of
# this table must not let anybody finish a login that somebody else started.

#: Wrong codes allowed against one pending login before it is thrown away.
#:
#: Five. A six-digit code is a million possibilities, so this is not what
#: stops guessing on its own - `core.login_guard` already counts failures per
#: user and per address. What it stops is one captured pending token being
#: used as an unlimited oracle.
MAX_PENDING_ATTEMPTS = 5


def new_pending_token() -> str:
    return secrets.token_urlsafe(32)


def hash_pending(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()
