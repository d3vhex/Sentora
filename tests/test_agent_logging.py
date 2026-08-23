"""The agent's log must not grow without bound, or say nothing at length.

`agent.log` reached 55 MB on an endpoint running for a few weeks: a plain
FileHandler in append mode, and nothing ever reclaimed it. Measured over 13.3
hours of real output it was writing 5.1 MB a day, and 56% of the lines carried
no information - repeated constant banners, decorative rules, and per-cycle
reports that nothing had happened.

Two independent guards, because they fail differently: rotation caps the
worst case whatever the code does, and quietening the producers means the
capped window covers days rather than hours.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

AGENT = pathlib.Path(__file__).resolve().parent.parent / "Sentora"
MAIN = AGENT / "main.py"
SOAR = AGENT / "modules" / "soar" / "soar.py"
EXTRACTOR = AGENT / "modules" / "log_extractor" / "log_extractor.py"


# --------------------------------------------------------------------------
# The cap
# --------------------------------------------------------------------------

def test_the_agent_log_rotates():
    text = MAIN.read_text(encoding="utf-8")
    assert "RotatingFileHandler" in text, "agent.log has no rotation"
    assert re.search(r"logging\.FileHandler\(\s*AGENT_LOG_PATH", text) is None, (
        "a plain FileHandler on AGENT_LOG_PATH appends forever"
    )


def test_rotation_is_bounded_and_keeps_backups():
    text = MAIN.read_text(encoding="utf-8")
    block = text[text.index("RotatingFileHandler("):][:600]
    assert "maxBytes" in block and "backupCount" in block

    # backupCount=0 rotates by truncating and keeps no history, which would
    # discard exactly the window someone reaches for after an incident.
    m = re.search(r'AGENT_LOG_BACKUPS", "(\d+)"', text)
    assert m and int(m.group(1)) >= 1, "rotation keeps no previous log"


def test_rotation_is_configurable():
    """An endpoint with a small disk needs a smaller ceiling than the default."""
    text = MAIN.read_text(encoding="utf-8")
    assert "AGENT_LOG_MAX_BYTES" in text
    assert "AGENT_LOG_BACKUPS" in text


# --------------------------------------------------------------------------
# The producers
# --------------------------------------------------------------------------

def test_the_host_banner_is_not_repeated_per_send():
    """4376 copies of the same constant string in thirteen hours."""
    text = MAIN.read_text(encoding="utf-8")
    assert 'sent (IP: {public_ip}, OS: {OS_INFO})' not in text
    assert '[*] Host: {OS_INFO}' in text, "the banner is no longer logged at all"


def test_soar_does_not_draw_rules_around_every_cycle():
    text = SOAR.read_text(encoding="utf-8")
    assert 'self.logger.info("=" * 60)' not in text


def test_an_idle_soar_cycle_logs_nothing_at_info():
    """The cycle runs every ~30s; only a cycle that did something is news."""
    tree = ast.parse(SOAR.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "process_events")
    info_calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                  and getattr(n.func, "attr", "") == "info"]
    for call in info_calls:
        # every info() must sit under a condition
        assert any(isinstance(p, ast.If) for p in ast.walk(fn)
                   if call in ast.walk(p)), "unconditional info() in the SOAR cycle"


def test_siem_stats_is_one_line():
    text = EXTRACTOR.read_text(encoding="utf-8")
    assert 'json.dumps(stats, indent=2)' not in text, (
        "pretty-printed stats cost eight lines a minute"
    )


def test_siem_stats_skips_unchanged_reports():
    tree = ast.parse(EXTRACTOR.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "stats_reporter")
    assert any(isinstance(n, ast.Continue) for n in ast.walk(fn)), (
        "stats_reporter logs on every tick regardless of whether anything moved"
    )
