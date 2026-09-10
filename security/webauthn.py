"""Security keys and passkeys as a second factor.

TOTP already covers the case this console most needs covering - a password
that has been reused or read out of a browser. What it does not cover is
phishing: a six-digit code typed into a convincing copy of this login page
works just as well on the real one, and the operator has no way to tell.

WebAuthn does cover it, because the browser signs over the origin it is
actually talking to. A key registered against `sentora.corp.local` produces
nothing usable on `sentora-corp.example.com`, no matter how good the copy is
or how carefully the operator was fooled.

The whole design question here was configuration, and the answer is that there
is none.

**The RP ID comes from the request, not from a setting.** WebAuthn ties a
credential to a "relying party ID", which must be the origin's host or a
registrable suffix of it. Making that a config value creates a setting that
must agree with the URL people type, and the failure when it disagrees is a
browser error message about a `SecurityError` that names neither side. Deriving
it from the request means it is right by construction, and every deployment -
one laptop, or an estate with a real hostname - works without being told
anything.

**Not every origin can host a key, and the platform says which.** WebAuthn
requires a secure context, and its RP ID must be a *domain*: browsers reject an
IP address outright. So a console opened at `https://192.168.1.26:8000` cannot
register a security key, ever, and no amount of configuration changes that.
`usability()` answers that question for the origin in front of it, so the
console can say "not from this address, and here is why" rather than showing a
button that fails.

**A credential records the RP ID it was made for.** An operator who registers a
key at `https://localhost` and later moves the console to a hostname has a
credential the browser will not offer any more - it is scoped to the old
origin. Storing the RP ID lets the login step offer only the keys that can
actually work here, instead of presenting a prompt that times out.

**TOTP stays.** A key is an addition, not a replacement: losing the only
authenticator you own must not be the end of the account, and recovery codes
remain the way back in.

**The sign count is checked.** An authenticator that reports a counter lower
than the one we last saw has either been cloned or is a model that does not
implement counters at all. The first is the attack WebAuthn's counter exists to
catch; the second is common enough that refusing outright would lock out real
hardware. Zero means "not implemented" and is accepted; a decrease from a
non-zero value is refused.
"""
from __future__ import annotations

import ipaddress
import secrets

#: How long a registration or authentication challenge stays valid.
#:
#: Two minutes. The ceremony is a touch on a key; anything longer is a
#: challenge sitting in a table waiting to be replayed.
CHALLENGE_TTL_SECONDS = 120

#: What the browser shows in the prompt.
RP_NAME = "Sentora"

DDL_CREDENTIALS = """
CREATE TABLE IF NOT EXISTS user_webauthn (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    credential_id VARCHAR(512) NOT NULL,
    public_key    VARCHAR(1024) NOT NULL,
    rp_id         VARCHAR(255) NOT NULL,
    sign_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports    VARCHAR(128) NULL,
    nickname      VARCHAR(64) NULL,
    created_at    TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  TIMESTAMP NULL DEFAULT NULL,
    UNIQUE KEY uq_webauthn_cred (credential_id),
    KEY idx_webauthn_user (user_id, rp_id),
    CONSTRAINT fk_webauthn_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

# `credential_id` and `public_key` are base64url text rather than BLOB, so the
# rows survive a mysqldump through a text pipeline unchanged. Both are sized
# well above what current authenticators produce - a credential id is up to 1023
# bytes by spec, but everything in the field is far smaller, and a column too
# narrow is how this codebase lost telemetry to "Data too long" before.

DDL_CHALLENGES = """
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge  VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    INT NOT NULL,
    purpose    VARCHAR(16) NOT NULL,
    rp_id      VARCHAR(255) NOT NULL,
    origin     VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_challenge_expiry (expires_at),
    CONSTRAINT fk_challenge_user FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

# Server-side and single-use. A challenge kept only in the browser is a
# challenge the browser can choose, which is the replay this ceremony exists to
# prevent. The row is deleted when it is spent, so a captured response cannot be
# presented twice.
#
# `origin` is stored alongside `rp_id` because verification checks both, and
# checking the response against the origin the *response* claims is not a check
# at all.


class Unusable(Exception):
    """This origin cannot host a WebAuthn credential, and why."""


def split_host(host: str) -> tuple[str, str | None]:
    """`host:port` into its parts, tolerating IPv6 brackets.

    `request.host` carries the port, and an RP ID must not. Getting this wrong
    produces `localhost:8000`, which is not a registrable domain and which the
    browser refuses with an error naming neither the setting nor the cause.
    """
    host = (host or "").strip()
    if host.startswith("["):                       # [::1]:8000
        closing = host.find("]")
        if closing != -1:
            port = host[closing + 1:].lstrip(":") or None
            return host[1:closing], port
    if host.count(":") == 1:
        name, _, port = host.partition(":")
        return name, port or None
    return host, None                              # bare IPv6, or no port


def is_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def usability(host: str, scheme: str) -> tuple[bool, str]:
    """Can a security key be used from this origin? Returns (ok, reason).

    The reason is written for the operator reading it in the console, because
    every one of these is a dead end they would otherwise meet as a browser
    error with no explanation.
    """
    name, _ = split_host(host)
    if not name:
        return False, "The console could not determine its own address."

    secure = scheme == "https" or name == "localhost" or name == "127.0.0.1" or name == "::1"
    if not secure:
        return False, (
            f"This console is open over plain HTTP at {name}. A security key "
            f"needs a secure context — https, or localhost. Set TLS_ENABLED=1, "
            f"or open the console at https://."
        )

    if is_address(name):
        return False, (
            f"This console is open at the address {name}. A security key is "
            f"bound to a domain name, and browsers refuse an IP address as one, "
            f"so no key can be registered from here. Reach the console by a "
            f"hostname — set TLS_CN and TLS_SAN to a name that resolves on your "
            f"network, then open the console at that name. One-time codes work "
            f"from an address and are unaffected."
        )

    return True, ""


def relying_party(host: str, scheme: str) -> tuple[str, str]:
    """The (rp_id, origin) this ceremony must be bound to.

    Raises `Unusable` rather than returning something almost right. A ceremony
    started against an RP ID the browser will reject fails inside the browser,
    where the message is generic and the server sees nothing at all.
    """
    ok, reason = usability(host, scheme)
    if not ok:
        raise Unusable(reason)
    name, port = split_host(host)
    origin = f"{scheme}://{name}" + (f":{port}" if port else "")
    return name, origin


def new_challenge() -> str:
    """URL-safe and long. This is the value the authenticator signs over."""
    return secrets.token_urlsafe(32)


def counter_regressed(stored: int, presented: int) -> bool:
    """Has this authenticator gone backwards?

    A key that reports a lower counter than the one we recorded has been
    cloned: the copy does not know how many times the original has been used.
    That is the attack the counter exists to detect.

    Zero is not a regression. Plenty of authenticators - most platform
    passkeys, and every key that syncs between devices - do not implement a
    counter and send zero for ever. Treating that as a clone would refuse the
    most common hardware in the field, which is how a security control ends up
    switched off entirely.
    """
    if presented == 0 or stored == 0:
        return False
    return presented <= stored


def describe(credential: dict) -> str:
    """A short line for the console's list of registered keys."""
    name = (credential.get("nickname") or "").strip()
    if name:
        return name
    transports = (credential.get("transports") or "").strip()
    if "internal" in transports:
        return "This device"
    if "usb" in transports:
        return "USB security key"
    if "nfc" in transports or "ble" in transports:
        return "Wireless security key"
    return "Security key"
