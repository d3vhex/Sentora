"""Shapes across events, which no per-event rule can see.

The corpus case that motivated this: `t1110-password-spray`, five accounts
failing from one host in forty seconds. Sigma skips it with a reason, because
matching a rule against one event dict cannot express "count distinct users
where the source is the same".

Every test here drives the clock explicitly. A correlation bug is almost
always a timing bug, and one that only appears under a real clock is one
nobody can reproduce.
"""
from __future__ import annotations

import pytest

from core.correlation import (BUILTIN_RULES, CorrelationEngine,
                              CorrelationRule, default_engine,
                              techniques_covered)


def failed_logon(user: str, ip: str = "10.20.30.41") -> dict:
    return {"EventID": "4625", "TargetUserName": user, "IpAddress": ip,
            "WorkstationName": "WKSTN-14", "LogonType": "3"}


def good_logon(user: str, ip: str = "10.20.30.41") -> dict:
    return {"EventID": "4624", "TargetUserName": user, "IpAddress": ip,
            "LogonType": "3"}


def fire(engine, events, start=1000.0, step=1.0):
    """Feed events at a fixed cadence and collect what fired."""
    out = []
    for i, event in enumerate(events):
        out.extend(engine.observe(event, now=start + i * step))
    return out


# --------------------------------------------------------------------------
# Password spray
# --------------------------------------------------------------------------

def test_the_corpus_case_fires():
    """Five distinct accounts, one source, forty seconds - the case Sigma
    skips and the reason this module exists."""
    engine = default_engine()
    events = [failed_logon(u) for u in
              ("jdoe", "asmith", "rpatel", "mchen", "klopez")]
    found = fire(engine, events, step=8.0)

    assert [d.rule for d in found] == ["password_spray"]
    assert found[0].count == 5
    assert found[0].techniques == ("T1110.003",)
    assert "10.20.30.41" in found[0].summary()


def test_one_account_failing_repeatedly_is_not_a_spray():
    """The distinction the whole rule rests on. Many attempts against one
    account is brute force; counting attempts rather than accounts would turn
    each into the other."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES
                                if r.name == "password_spray"])
    found = fire(engine, [failed_logon("jdoe") for _ in range(20)])
    assert found == []


def test_accounts_spread_beyond_the_window_do_not_accumulate():
    """A help desk that resets five passwords over an afternoon is not an
    attack. A spray is fast by construction - the attacker is staying under
    per-account lockout, so the accounts are hit close together."""
    engine = default_engine()
    found = fire(engine, [failed_logon(u) for u in
                          ("a", "b", "c", "d", "e")], step=120.0)
    assert found == []


def test_failures_from_different_sources_are_different_windows():
    """Grouping is per source. Five accounts failing from five different
    machines is five people getting their password wrong."""
    engine = default_engine()
    events = [failed_logon(u, ip=f"10.0.0.{i}")
              for i, u in enumerate(("a", "b", "c", "d", "e"))]
    assert fire(engine, events) == []


def test_an_event_with_no_group_value_is_ignored():
    """Not bucketed under the empty string. Lumping events with no source
    address together counts unrelated failures as one attacker, which is this
    rule class's most confusing false positive."""
    engine = default_engine()
    events = [{"EventID": "4625", "TargetUserName": u, "IpAddress": ""}
              for u in ("a", "b", "c", "d", "e", "f", "g")]
    assert fire(engine, events) == []


# --------------------------------------------------------------------------
# Firing once
# --------------------------------------------------------------------------

def test_a_sustained_spray_reports_once_not_once_per_event():
    """The failure that matters is not missing a spray, it is reporting it
    sixty times.

    This is the same bug class that had the defensive sweep re-queueing 4,919
    duplicate alerts: a condition that stays true keeps producing work unless
    something says "already told you".
    """
    engine = default_engine()
    events = [failed_logon(f"user{i}") for i in range(60)]
    found = [d for d in fire(engine, events, step=1.0) if d.rule == "password_spray"]
    assert len(found) == 1


def test_it_fires_again_once_the_cooldown_has_passed():
    """Silence is a cooldown, not a permanent mute. An attacker who pauses and
    resumes is still an attacker, and an alert nobody ever gets again is
    indistinguishable from a detection that was removed."""
    engine = default_engine()
    users = ("a", "b", "c", "d", "e")

    first = fire(engine, [failed_logon(u) for u in users], start=1000.0)
    later = fire(engine, [failed_logon(u) for u in users], start=9000.0)

    assert len(first) == 1
    assert len(later) == 1


# --------------------------------------------------------------------------
# Brute force, and the one that matters
# --------------------------------------------------------------------------

def test_repeated_failures_against_one_account_fire_brute_force():
    engine = CorrelationEngine([r for r in BUILTIN_RULES if r.name == "brute_force"])
    found = fire(engine, [failed_logon("jdoe") for _ in range(10)])
    assert [d.rule for d in found] == ["brute_force"]
    assert found[0].count == 10


def test_nine_failures_do_not_fire():
    """Thresholds are exclusive of the value below them, and off-by-one here
    means either a rule that never fires or one that fires on ordinary
    typing."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES if r.name == "brute_force"])
    assert fire(engine, [failed_logon("jdoe") for _ in range(9)]) == []


def test_a_success_after_failures_is_the_one_that_matters():
    """Failures alone are a symptom. Failures followed by a success on the
    same account is the guess landing, which is why it is CRITICAL and the
    other is HIGH."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES
                                if r.name == "successful_logon_after_failures"])
    found = fire(engine, [failed_logon("jdoe"), failed_logon("jdoe"),
                          good_logon("jdoe")])
    assert [d.rule for d in found] == ["successful_logon_after_failures"]
    assert found[0].severity == "CRITICAL"


def test_a_clean_logon_on_its_own_fires_nothing():
    """Otherwise every successful logon on the estate is an alert."""
    engine = default_engine()
    assert fire(engine, [good_logon("jdoe") for _ in range(20)]) == []


def test_failures_for_one_account_and_a_success_for_another_do_not_combine():
    """Grouped by account. Combining them would report an incident every time
    somebody logged in while somebody else was mistyping."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES
                                if r.name == "successful_logon_after_failures"])
    assert fire(engine, [failed_logon("jdoe"), good_logon("asmith")]) == []


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------

def test_tracked_groups_are_capped():
    """The group key is attacker-controlled - a username, a source address. An
    unbounded counter keyed on that is a memory exhaustion primitive, not a
    detection."""
    engine = default_engine(max_groups=64)
    for i in range(5000):
        engine.observe(failed_logon("jdoe", ip=f"10.{i // 256}.{i % 256}.1"),
                       now=1000.0 + i)
    assert engine.tracked_groups <= 64
    assert engine.evictions > 0


def test_old_timestamps_are_dropped_from_a_live_window():
    """Otherwise a group that stays busy for a week holds a week of
    timestamps, and the cap on groups says nothing about the size of one."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES if r.name == "brute_force"])
    for i in range(10_000):
        engine.observe(failed_logon("jdoe"), now=1000.0 + i * 10)
    window = next(iter(engine._windows.values()))
    assert len(window.events) <= 64


# --------------------------------------------------------------------------
# Robustness
# --------------------------------------------------------------------------

def test_a_rule_that_raises_does_not_stop_the_others():
    """This runs on the collection thread. One malformed event must cost one
    event, not the host's telemetry."""
    def explode(_event):
        raise ValueError("bad field")

    broken = CorrelationRule(
        name="broken", title="x", severity="HIGH", techniques=(),
        window_s=60, threshold=1, matches=explode, group_by=lambda e: "g")

    engine = CorrelationEngine([broken] + [r for r in BUILTIN_RULES
                                           if r.name == "brute_force"])
    found = fire(engine, [failed_logon("jdoe") for _ in range(10)])
    assert [d.rule for d in found] == ["brute_force"]


def test_an_empty_event_is_harmless():
    engine = default_engine()
    assert engine.observe({}, now=1000.0) == []
    assert engine.observe({"EventID": "4625"}, now=1000.0) == []


# --------------------------------------------------------------------------
# It has to reach the rest of the platform
# --------------------------------------------------------------------------

@pytest.mark.parametrize("rule", BUILTIN_RULES, ids=lambda r: r.name)
def test_every_rule_carries_techniques_and_a_false_positive_note(rule):
    """Techniques feed the ATT&CK coverage page the same way Sigma tags do.
    A rule without one detects something and contributes nothing to the
    picture of what is covered."""
    assert rule.techniques, rule.name
    assert rule.falsepositives, rule.name


def test_the_techniques_are_ones_sigma_cannot_reach():
    """If a shape were already covered by a per-event rule this module would
    be adding cost without adding coverage."""
    from core.sigma_loader import load_dir
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    sigma = load_dir(root / "Sentora" / "conf" / "sigma").techniques
    assert "T1110.003" in techniques_covered()
    assert "T1110.003" not in sigma


# --------------------------------------------------------------------------
# Linux, end to end from the raw line
# --------------------------------------------------------------------------

def syslog(line: str) -> dict:
    from core.sigma_loader import text_event_fields
    return text_event_fields(line, "/var/log/auth.log")


def test_an_ssh_spray_fires_from_raw_auth_log_lines():
    """The whole Linux chain: a text line, parsed into fields, counted across
    a window. None of the three steps is useful without the other two - which
    is why the syslog parsing and this module landed together."""
    engine = default_engine()
    lines = [
        f"Aug 25 03:14:0{i} web-01 sshd[12{i}]: Failed password for "
        f"invalid user {u} from 185.7.2.9 port 5122{i} ssh2"
        for i, u in enumerate(("admin", "root", "test", "oracle", "postgres"))
    ]
    found = fire(engine, [syslog(line) for line in lines], step=3.0)
    assert [d.rule for d in found] == ["password_spray"]
    assert found[0].group == "185.7.2.9"
    assert found[0].count == 5


def test_an_ssh_guess_landing_is_critical():
    """Failures then a success on the same account. On an internet-facing host
    this is the single most important thing in auth.log."""
    engine = CorrelationEngine([r for r in BUILTIN_RULES
                                if r.name == "successful_logon_after_failures"])
    lines = [
        "Aug 25 03:14:01 web-01 sshd[1]: Failed password for jdoe from 1.2.3.4 port 1 ssh2",
        "Aug 25 03:14:05 web-01 sshd[2]: Failed password for jdoe from 1.2.3.4 port 2 ssh2",
        "Aug 25 03:14:09 web-01 sshd[3]: Accepted password for jdoe from 1.2.3.4 port 3 ssh2",
    ]
    found = fire(engine, [syslog(line) for line in lines])
    assert [d.severity for d in found] == ["CRITICAL"]


def test_ordinary_ssh_traffic_fires_nothing():
    engine = default_engine()
    lines = [
        f"Aug 25 03:1{i}:00 web-01 sshd[{i}]: Accepted publickey for deploy "
        f"from 10.0.0.{i} port 40{i} ssh2" for i in range(1, 9)
    ]
    assert fire(engine, [syslog(line) for line in lines], step=60.0) == []


def test_one_predicate_covers_both_platforms():
    """A spray is the same shape wherever it happens. Two rule sets is how the
    thresholds drift apart - the Linux copy gets tuned and the Windows one
    does not."""
    from core.correlation import _is_failed_logon, _is_successful_logon
    assert _is_failed_logon({"EventID": "4625"})
    assert _is_failed_logon({"AuthResult": "failure"})
    assert _is_successful_logon({"EventID": "4624"})
    assert _is_successful_logon({"AuthResult": "success"})
    assert not _is_failed_logon({"EventID": "4624"})
    assert not _is_failed_logon({})


# --------------------------------------------------------------------------
# It has to reach the queue
# --------------------------------------------------------------------------

def _extractor():
    """Import the agent's extractor, with the agent root on the path."""
    import importlib.util
    import pathlib
    import sys

    root = pathlib.Path(__file__).resolve().parent.parent
    agent = str(root / "Sentora")
    if agent not in sys.path:
        sys.path.insert(0, agent)
    path = root / "Sentora" / "modules" / "log_extractor" / "log_extractor.py"
    spec = importlib.util.spec_from_file_location("_le_corr", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except ImportError as e:
        pytest.skip(f"agent dependency unavailable: {e}")
    return module


def test_a_fired_window_becomes_an_event_of_its_own():
    """Not a relabelling of the event that happened to complete it. The fifth
    failed logon is no more interesting than the first, so marking it CRITICAL
    would show an analyst a routine 4625 with no explanation attached."""
    module = _extractor()
    engine = default_engine()
    enricher = module.EventEnricher()

    emitted = []
    for user in ("jdoe", "asmith", "rpatel", "mchen", "klopez"):
        emitted += module.correlated_events(
            engine, failed_logon(user), enricher, "Security")

    assert len(emitted) == 1
    event = emitted[0]
    assert event.severity == "HIGH"
    assert event.techniques == ["T1110.003"]
    assert event.rule_title == "Password Spray"
    assert "5 distinct accounts" in event.raw_message


def test_two_detections_of_the_same_window_do_not_collide_in_the_dedup_filter():
    """The dedup filter exists for repeated log lines and keys on a hash of
    the text. A spray detected, quiet through its cooldown, then detected
    again produces identical text - so without a distinct hash the second one
    is silently dropped as a duplicate."""
    module = _extractor()
    enricher = module.EventEnricher()
    users = ("a", "b", "c", "d", "e")

    engine = default_engine()
    first = second = None
    for i, u in enumerate(users):
        got = module.correlated_events(engine, failed_logon(u), enricher,
                                       "Security", when=1000.0 + i)
        if got:
            first = got[0]
    # Same engine, clock advanced past the cooldown - not a fresh engine,
    # which would reset the sequence and hide exactly the collision this is
    # checking for.
    for i, u in enumerate(users):
        got = module.correlated_events(engine, failed_logon(u), enricher,
                                       "Security", when=9000.0 + i)
        if got:
            second = got[0]

    assert first is not None and second is not None
    assert first.raw_message == second.raw_message
    assert first.event_hash != second.event_hash


def test_a_correlation_failure_does_not_stop_collection():
    """This runs on the collection thread. A bug here must cost a detection,
    not the host's telemetry."""
    module = _extractor()

    class Broken:
        rules = []

        def observe(self, _fields):
            raise RuntimeError("boom")

    assert module.correlated_events(
        Broken(), {"EventID": "4625"}, module.EventEnricher(), "Security") == []


def test_no_correlator_is_not_an_error():
    """`core/` may be absent on a partial deployment; the agent degrades to
    the regex rules rather than failing to start."""
    module = _extractor()
    assert module.correlated_events(None, {"EventID": "4625"},
                                    module.EventEnricher(), "Security") == []
