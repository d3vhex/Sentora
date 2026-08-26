"""Detections that are a shape across events rather than a property of one.

Sigma matches a rule against one event dict and `conf/rules.yaml` matches a
regex against one line. Neither can express "count distinct users where the
source is the same, within a window" - so password spray, brute force and
beaconing were not missed by a rule, they had no rule that could exist.

Not Sigma's own `correlation:` spec: it needs a stateful engine buffering
events per rule and resolving references between them, which is a lot of
machinery on something running on every endpoint, for a handful of shapes.

Three properties are load-bearing:

**Fires once per window.** A condition that stays true keeps producing work
unless something says "already told you" - the bug class that had the
defensive sweep re-queueing 4,919 duplicate alerts.

**Bounded memory.** Group keys are attacker-supplied usernames and source
addresses; an unbounded counter on those is a memory exhaustion primitive.

**Two engines, because two vantage points see different attacks.**
`default_engine()` runs on the agent, where an attack against one machine is
visible in full - and is per host, so one account sprayed across fifty
machines once each is invisible to all of them. That is the more competent
attack. `fleet_engine()` runs in the ingest path and counts distinct hosts,
with wider windows because walking an estate is slower than walking a user
list. It reconstructs named fields via `sigma_loader.agent_event_fields`.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Callable, Iterable


@dataclass(frozen=True)
class Detection:
    """A window that fired."""

    rule: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    group: str
    count: int
    window_s: int
    detail: str = ""
    fired_at: float = 0.0
    # Distinguishes two firings of the same window, which say the same words.
    # A timestamp cannot: it is written at second resolution downstream, so
    # two detections inside one second look identical to a dedup filter that
    # keys on text.
    seq: int = 0

    def summary(self) -> str:
        return (f"{self.title}: {self.detail or self.count} "
                f"within {self.window_s}s [{self.group}]")


@dataclass
class CorrelationRule:
    """One shape.

    `group_by` is what the count is per. Events with no value for it are
    ignored rather than bucketed under the empty string, which would count
    unrelated events as one attacker.

    `distinct_by` separates spray from brute force: many *accounts* from one
    source, versus many attempts against one account. Counting the wrong one
    turns each into the other.
    """

    name: str
    title: str
    severity: str
    techniques: tuple[str, ...]
    window_s: int
    threshold: int
    matches: Callable[[dict], bool]
    group_by: Callable[[dict], str]
    distinct_by: Callable[[dict], str] | None = None
    cooldown_s: int = 300
    detail: str = ""
    falsepositives: tuple[str, ...] = ()


@dataclass
class _Window:
    """Timestamps, and the distinct values seen at each, for one group."""

    events: deque = field(default_factory=deque)
    fired_at: float = 0.0


class CorrelationEngine:
    """Feed it events; it returns the windows that fired.

    Synchronous and allocation-light on purpose: it runs on the hot path for
    every event collected.
    """

    def __init__(self, rules: Iterable[CorrelationRule], max_groups: int = 2048):
        self.rules = list(rules)
        self.max_groups = max(1, int(max_groups))
        # (rule name, group) -> _Window, in least-recently-seen order.
        self._windows: OrderedDict[tuple[str, str], _Window] = OrderedDict()
        self.evictions = 0
        self._seq = 0

    def observe(self, event: dict, now: float | None = None) -> list[Detection]:
        now = time.time() if now is None else now
        found: list[Detection] = []

        for rule in self.rules:
            try:
                if not rule.matches(event):
                    continue
                group = str(rule.group_by(event) or "").strip()
            except Exception:
                # One malformed event must not kill the collection thread.
                continue
            if not group:
                continue

            key = (rule.name, group)
            window = self._windows.get(key)
            if window is None:
                window = _Window()
                self._windows[key] = window
                self._evict()
            self._windows.move_to_end(key)

            value = ""
            if rule.distinct_by is not None:
                try:
                    value = str(rule.distinct_by(event) or "")
                except Exception:
                    value = ""

            window.events.append((now, value))
            cutoff = now - rule.window_s
            while window.events and window.events[0][0] < cutoff:
                window.events.popleft()

            if rule.distinct_by is None:
                count = len(window.events)
            else:
                count = len({v for _, v in window.events if v})

            if count < rule.threshold:
                continue
            if now - window.fired_at < rule.cooldown_s:
                continue

            window.fired_at = now
            self._seq += 1
            found.append(Detection(
                rule=rule.name, title=rule.title, severity=rule.severity,
                techniques=tuple(rule.techniques), group=group, count=count,
                window_s=rule.window_s,
                detail=(rule.detail.format(count=count, group=group)
                        if rule.detail else ""),
                fired_at=now, seq=self._seq,
            ))

        return found

    def _evict(self) -> None:
        while len(self._windows) > self.max_groups:
            self._windows.popitem(last=False)
            self.evictions += 1

    @property
    def tracked_groups(self) -> int:
        return len(self._windows)


# ---------------------------------------------------------------------------
# The shapes
# ---------------------------------------------------------------------------

def _get(event: dict, *names: str) -> str:
    for name in names:
        value = event.get(name)
        if value:
            return str(value)
    return ""


def _eid(event: dict) -> str:
    return str(event.get("EventID") or "")


def _is_failed_logon(event: dict) -> bool:
    """A failed authentication, on either platform.

    Windows says EventID 4625; Linux has no equivalent, so
    `sigma_loader.text_event_fields` synthesises `AuthResult`. One predicate
    rather than two rule sets, because duplicating them per platform is how
    the thresholds drift apart.
    """
    return _eid(event) == "4625" or str(event.get("AuthResult", "")).lower() == "failure"


def _is_successful_logon(event: dict) -> bool:
    return _eid(event) == "4624" or str(event.get("AuthResult", "")).lower() == "success"


BUILTIN_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="password_spray",
        title="Password Spray",
        severity="HIGH",
        techniques=("T1110.003",),
        # Short on purpose: a spray hits many accounts close together to
        # stay under per-account lockout.
        window_s=300,
        threshold=5,
        matches=_is_failed_logon,
        group_by=lambda e: _get(e, "IpAddress", "SourceIp", "WorkstationName"),
        distinct_by=lambda e: _get(e, "TargetUserName", "User").lower(),
        detail="{count} distinct accounts failed from {group}",
        falsepositives=(
            "A misconfigured service account after a password change, which "
            "fails against several accounts from one host in exactly this "
            "shape",
        ),
    ),
    CorrelationRule(
        name="brute_force",
        title="Brute Force Against One Account",
        severity="HIGH",
        techniques=("T1110.001",),
        window_s=300,
        threshold=10,
        matches=_is_failed_logon,
        group_by=lambda e: _get(e, "TargetUserName", "User").lower(),
        distinct_by=None,          # attempts, not accounts
        detail="{count} failed logons for {group}",
        falsepositives=(
            "A user whose saved credential is stale, retrying automatically",
        ),
    ),
    CorrelationRule(
        name="successful_logon_after_failures",
        title="Successful Logon After Repeated Failures",
        severity="CRITICAL",
        techniques=("T1110",),
        # Failures alone are a symptom; failures then a success on the same
        # account is the guess landing. Separate from brute_force so the
        # severity can differ.
        window_s=600,
        threshold=2,
        matches=lambda e: _is_failed_logon(e) or _is_successful_logon(e),
        group_by=lambda e: _get(e, "TargetUserName", "User").lower(),
        # Needs both a failure and a success, so the distinct value is which
        # of the two this was - not the event ID, which differs per platform.
        distinct_by=lambda e: "success" if _is_successful_logon(e) else "failure",
        detail="failures then a success for {group}",
        falsepositives=(
            "Someone mistyping their password and then getting it right, "
            "which is why the threshold on brute_force exists separately",
        ),
    ),
    CorrelationRule(
        name="rapid_account_creation",
        title="Several Accounts Created In Quick Succession",
        severity="HIGH",
        techniques=("T1136.001",),
        window_s=600,
        threshold=3,
        matches=lambda e: _eid(e) == "4720",
        group_by=lambda e: _get(e, "SubjectUserName") or "unknown",
        distinct_by=lambda e: _get(e, "TargetUserName").lower(),
        detail="{count} accounts created by {group}",
        falsepositives=("Bulk provisioning, which does exactly this",),
    ),
    CorrelationRule(
        name="service_install_burst",
        title="Several Services Installed In Quick Succession",
        severity="HIGH",
        techniques=("T1543.003",),
        # Lateral movement tooling installs a service per host it reaches.
        window_s=600,
        threshold=3,
        matches=lambda e: _eid(e) == "7045",
        group_by=lambda e: "host",
        distinct_by=lambda e: _get(e, "ServiceName").lower(),
        detail="{count} services installed",
        falsepositives=("A software deployment window",),
    ),
]


# ---------------------------------------------------------------------------
# Shapes only the server can see
# ---------------------------------------------------------------------------
#
# The rules above are per host, so one account sprayed across fifty machines
# once each is invisible to every agent - and that is the more competent
# attack, staying under per-account lockout *and* per-host thresholds.
#
# These run in the ingest path, where `agent` is on the event, so the count is
# over distinct hosts rather than distinct accounts.

def _host(event: dict) -> str:
    return str(event.get("agent") or event.get("Computer") or "")


FLEET_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="fleet_spray",
        title="Authentication Failures Across Many Hosts From One Source",
        severity="CRITICAL",
        techniques=("T1110.003",),
        # Wider than the per-host rule: walking an estate is slower than
        # walking a user list, and being slow is the point of the technique.
        window_s=1800,
        threshold=5,
        matches=_is_failed_logon,
        group_by=lambda e: _get(e, "IpAddress", "SourceIp"),
        distinct_by=_host,
        detail="{count} distinct hosts saw failures from {group}",
        falsepositives=(
            "A service account with a stale password, configured on many "
            "hosts, which fails on all of them at once after a rotation",
        ),
    ),
    CorrelationRule(
        name="fleet_account_spray",
        title="One Account Failing Across Many Hosts",
        severity="HIGH",
        techniques=("T1110.003", "T1078"),
        window_s=1800,
        threshold=5,
        matches=_is_failed_logon,
        group_by=lambda e: _get(e, "TargetUserName", "User").lower(),
        distinct_by=_host,
        detail="{group} failed on {count} distinct hosts",
        falsepositives=(
            "A domain account whose password changed, retried by a client on "
            "every machine the user is logged into",
        ),
    ),
    CorrelationRule(
        name="fleet_service_install",
        title="The Same Service Installed Across Many Hosts",
        severity="CRITICAL",
        techniques=("T1021.002", "T1543.003"),
        # The same service name across the estate in half an hour is either
        # a deployment or somebody walking it.
        window_s=1800,
        threshold=3,
        matches=lambda e: _eid(e) == "7045",
        group_by=lambda e: _get(e, "ServiceName").lower(),
        distinct_by=_host,
        detail="{group} installed on {count} distinct hosts",
        falsepositives=("A software deployment window",),
    ),
    CorrelationRule(
        name="fleet_account_creation",
        title="Accounts Created Across Many Hosts",
        severity="HIGH",
        techniques=("T1136.001",),
        window_s=3600,
        threshold=3,
        matches=lambda e: _eid(e) == "4720",
        group_by=lambda e: _get(e, "TargetUserName").lower(),
        distinct_by=_host,
        detail="{group} created on {count} distinct hosts",
        falsepositives=("Provisioning a local service account estate-wide",),
    ),
]


def default_engine(max_groups: int = 2048) -> CorrelationEngine:
    """The per-host engine, for the agent."""
    return CorrelationEngine(BUILTIN_RULES, max_groups=max_groups)


def fleet_engine(max_groups: int = 8192) -> CorrelationEngine:
    """The cross-host engine, for the ingest path.

    A larger group cap than the agent's - estate-wide cardinality is higher -
    but still bounded, because the key is still attacker-supplied.
    """
    return CorrelationEngine(FLEET_RULES, max_groups=max_groups)


def techniques_covered() -> set[str]:
    """For the ATT&CK coverage page, which reads Sigma's tags the same way."""
    return {t for r in BUILTIN_RULES + FLEET_RULES for t in r.techniques}
