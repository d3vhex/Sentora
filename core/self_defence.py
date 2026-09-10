"""Attacks on the platform itself, recorded where somebody will see them.

The server already detects most of this. It just does not tell anyone.

A brute-force against the console produces `login_logs` rows and eventually a
lockout, and the console's alert view shows nothing. An agent key that has been
revoked keeps trying and the server prints

    [agent-link] refused a connection from 203.0.113.9

to a container log. An operator hitting agent routes they have no permission
for lands in `audit_logs` as `PROXY_DENIED`, in a table nobody opens unless
they are already investigating something.

So the platform watches every host in the fleet and is the one machine nobody
watches. That is worth fixing on its own, and it is worth fixing *here* rather
than by adding another table nobody reads: these become events of the same
shape as everything else, so they sort, filter and alert beside the telemetry
the console already surfaces.

Three rules this module exists to keep:

**Recording must never break the thing it is recording.** Every writer here
swallows its own failure. A platform that refuses a login because it could not
journal the refusal has turned a monitoring gap into an outage.

**A severity is a claim, so it has to be earned.** One failed password is not
an incident and must not be stored as one; the fifth from the same address in
a minute is. The counting already happens in `core.login_guard`, and this
module records the *conclusion* rather than every attempt.

**Never store a credential.** These records describe attempts on secrets, and
the obvious fields to include - the password tried, the agent key presented -
are exactly the ones that turn an audit trail into a second breach. What is
kept is enough to act on: who, from where, how many, and what they were after.
"""
from __future__ import annotations

import datetime


#: The event kinds this platform raises about itself.
#:
#: Named rather than free text. A severity that varies by call site is a
#: severity nobody can filter on, and the first version of anything like this
#: always grows six spellings of "login failure".
KINDS: dict[str, tuple[str, str]] = {
    # kind: (severity, what it means)
    "LOGIN_LOCKOUT": (
        "HIGH",
        "Repeated failed logins crossed the lockout threshold. Somebody is "
        "guessing, or an integration is using a credential that has changed."),
    "AGENT_KEY_REJECTED": (
        "HIGH",
        "A channel was opened with a key this server does not recognise. Any "
        "agent whose key was revoked will do this; so will anyone who found a "
        "key that no longer works."),
    "FLEET_KEY_ON_CHANNEL": (
        "CRITICAL",
        "The fleet-wide secret was presented on the agent channel, which is "
        "refused. That channel carries /self_destruct, so a leaked master key "
        "must not open one against every endpoint at once."),
    "PERMISSION_DENIED": (
        "MEDIUM",
        "An authenticated operator reached for something their role does not "
        "allow. One is a mis-click; a run of them is somebody mapping what "
        "they can touch."),
    "ENROLMENT_TOKEN_REUSED": (
        "HIGH",
        "An enrolment token was presented after it had already been used. The "
        "token is a one-time credential, so a second use means it leaked."),
    "TOTP_CODE_REPLAYED": (
        "HIGH",
        "A second-factor code that had already been used was presented again. "
        "The code is valid for its whole thirty-second step, so this is what "
        "somebody watching one being typed would try."),
    "RECOVERY_CODE_USED": (
        "MEDIUM",
        "Somebody signed in with a recovery code instead of an authenticator. "
        "Usually an honest lost phone; the other reading is a stolen password "
        "and a stolen list."),
    "TOTP_DISABLE_REFUSED": (
        "HIGH",
        "A wrong password was given when turning off two-factor. A hijacked "
        "session trying to remove the control that would have stopped it "
        "looks exactly like this."),
    "WEBAUTHN_COUNTER_REGRESSED": (
        "CRITICAL",
        "A security key presented a signature counter lower than the last one "
        "this server saw. That is what a copy of the key looks like: the copy "
        "does not know how many times the original has been used. The only "
        "other reading is a replayed response, and neither is benign."),
}

# `TLS_DOWNGRADE_REFUSED` was defined here and is deliberately gone.
#
# It described an agent trying the plaintext ingest port after the deployment
# required TLS - and `INGEST_TLS_REQUIRED=1` does not open that listener at
# all, so the server never sees the connection. The kind could not be raised
# by design.
#
# Making it raisable would mean binding the port and refusing politely, and
# that is worse for exactly the agents it would report. A build older than the
# receipt frame marks its rows sent once `sendall` returns; a clean close
# after we read its name would let it do that and lose the batch. ECONNREFUSED
# raises inside `sendall`, so the rows stay put.
#
# The visibility is not lost, it is on the other side: a refused send becomes
# `record_send_failure` on the agent, and the telemetry health view reports
# the table as `send failing` with the connection error and counts it as
# broken. That is the same fact, reported by the half of the system that can
# report it without risking anybody's data.

#: Severity order, so a caller can compare without hardcoding a list.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def describe(kind: str) -> tuple[str, str]:
    """(severity, explanation) for a kind, or a safe default.

    Unknown kinds are MEDIUM rather than dropped. A caller that invents a name
    is a bug, but losing the event is worse than filing it under the wrong
    heading - and MEDIUM is visible without crying wolf.
    """
    return KINDS.get(kind, ("MEDIUM", "Unrecognised platform event."))


DDL = """
CREATE TABLE IF NOT EXISTS platform_events (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    kind        VARCHAR(64) NOT NULL,
    severity    VARCHAR(16) NOT NULL,
    subject     VARCHAR(255) NULL,
    source_ip   VARCHAR(64) NULL,
    detail      TEXT NULL,
    occurrences INT UNSIGNED NOT NULL DEFAULT 1,
    first_seen  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_pe_kind (kind),
    KEY idx_pe_seen (last_seen),
    KEY idx_pe_group (kind, subject, source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

#: How long a repeat folds into the previous row instead of making a new one.
#:
#: Without this a brute-force writes a row per attempt and the view that is
#: supposed to make the attack visible becomes the thing that hides it. With
#: it, one attack is one row whose `occurrences` climbs - which is also the
#: number an operator actually wants.
COALESCE_WINDOW_MINUTES = 10


def record(cursor, kind: str, *, subject: str = "", source_ip: str = "",
           detail: str = "") -> None:
    """File one platform security event, folding repeats together.

    Takes a cursor rather than opening its own connection: these are raised
    from inside request handlers that already hold one, and a second
    connection per failed login is how recording an attack becomes a way to
    amplify it.
    """
    severity, _ = describe(kind)
    subject = (subject or "")[:255]
    source_ip = (source_ip or "")[:64]

    cursor.execute(DDL)
    cursor.execute(
        "UPDATE platform_events SET occurrences = occurrences + 1, "
        "       last_seen = CURRENT_TIMESTAMP, detail = %s "
        " WHERE kind = %s AND subject = %s AND source_ip = %s "
        "   AND last_seen > (NOW() - INTERVAL %s MINUTE) "
        " ORDER BY id DESC LIMIT 1",
        (detail[:1000], kind, subject, source_ip, COALESCE_WINDOW_MINUTES))
    if cursor.rowcount:
        return

    cursor.execute(
        "INSERT INTO platform_events (kind, severity, subject, source_ip, detail) "
        "VALUES (%s, %s, %s, %s, %s)",
        (kind, severity, subject, source_ip, detail[:1000]))


def summarise(rows) -> dict:
    """Counts by severity for a set of rows, for the console's header.

    Sums `occurrences` rather than counting rows, because the rows are folded:
    "3 events" where one of them is 400 failed logins is the wrong number to
    put in front of somebody.
    """
    by_severity: dict[str, int] = {}
    attempts = 0
    for row in rows:
        severity = (row.get("severity") or "MEDIUM").upper()
        count = int(row.get("occurrences") or 1)
        by_severity[severity] = by_severity.get(severity, 0) + count
        attempts += count
    return {
        "by_severity": by_severity,
        "attempts": attempts,
        "worst": min(by_severity, key=lambda s: SEVERITY_RANK.get(s, 9),
                     default=None),
    }


def since(hours: int = 24) -> datetime.datetime:
    """The window boundary, as a naive UTC datetime to match the columns."""
    return (datetime.datetime.now(datetime.timezone.utc)
            .replace(tzinfo=None) - datetime.timedelta(hours=hours))
