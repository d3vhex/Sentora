"""Reports are read later, by someone who was not there.

A console is read by somebody who already knows what is missing. A PDF is
filed, forwarded and quoted months afterwards, so every number in it has to
carry whatever qualifies it or it will be quoted without.

That is not a hypothetical for this codebase. Three separate things have
shipped here that produced a confident, empty answer:

  - the AI triaged Fernet blobs and wrote fluent summaries of them
  - the vulnerability scanner asked OSV about a package named `enc::gAAAA...`
    and found nothing, for every agent, forever
  - an agent with no local database showed ONLINE with an IP and a hostname
    while sending no telemetry at all

Each looked exactly like good news on a page. So the assertions that matter
here are about caveats, not about layout.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from core.reporting import (Report, Section, build_agent_report,
                            build_fleet_report, filename_for)

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
TREE = ast.parse(APP)


def _handler(name):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
                and n.name == name)


def _caveats(report: Report) -> str:
    return " ".join(report.caveats).lower()


# --------------------------------------------------------------------------
# The agent report says what it could not see
# --------------------------------------------------------------------------

def test_a_silent_agent_is_called_out_not_rendered_as_clean():
    """The failure this exists for. An agent whose local database is
    unreachable sends nothing while still showing an address and a hostname,
    because those arrive in the connection header - so an empty report reads
    as a quiet host."""
    report = build_agent_report("web-01", {"no_telemetry": True, "info": {}})
    assert not report.is_trustworthy
    assert "sent no telemetry" in _caveats(report)
    assert "connection header" in _caveats(report)


def test_no_packages_is_flagged_rather_than_reported_as_no_vulnerabilities():
    """Zero findings from zero input is not a clean host."""
    report = build_agent_report("web-01", {"info": {}, "package_count": 0})
    assert "lack of input" in _caveats(report)


def test_undecryptable_events_are_counted_in_the_caveats():
    """These never reached the model at all, so the AI section understates
    what happened by exactly that many events."""
    report = build_agent_report("web-01", {
        "info": {}, "package_count": 10,
        "ai_insights": [
            {"critical_summary": "[NOT ANALYSED] The event could not be decrypted, so..."},
            {"critical_summary": "[NOT ANALYSED] The event could not be decrypted, so..."},
        ],
    })
    assert "2 event(s) could not be decrypted" in " ".join(report.caveats)
    assert "bootstrap" in _caveats(report)


def test_a_healthy_agent_produces_no_caveats():
    """Otherwise the section becomes noise and stops being read - which is
    how a real caveat gets skipped."""
    report = build_agent_report("web-01", {
        "info": {"os_info": "Ubuntu 24.04", "public_ip": "16.171.42.197"},
        "package_count": 412,
        "siem_events": [{"severity": "INFO", "message": "x"}],
        "ai_insights": [{"source_file": "Reviewed_siem_events"}],
    })
    assert report.is_trustworthy, report.caveats


def test_the_display_name_titles_the_report_and_the_real_name_survives():
    """The label is what a reader recognises; the identity is what matches a
    log line, a database name and a SOAR action."""
    report = build_agent_report("ip-172-31-42-49", {
        "display_name": "Web server 1", "info": {}})
    assert "Web server 1" in report.title
    assert "ip-172-31-42-49" in report.subtitle


def test_only_high_and_above_reach_the_detections_table():
    """A report listing every INFO event is a data dump nobody reads."""
    report = build_agent_report("web-01", {
        "info": {},
        "siem_events": [
            {"severity": "CRITICAL", "message": "lsass dump"},
            {"severity": "INFO", "message": "service started"},
        ],
    })
    detections = next(s for s in report.sections if s.title == "Detections")
    assert len(detections.rows) == 1
    assert "lsass" in detections.rows[0][-1]


def test_an_empty_section_says_which_kind_of_empty():
    """"No rows" and "nothing was collected" are different claims, and blank
    space asserts neither."""
    report = build_agent_report("web-01", {"info": {}, "siem_events": []})
    detections = next(s for s in report.sections if s.title == "Detections")
    assert "No SIEM events collected" in detections.empty_note


def test_correlation_findings_get_their_own_section():
    report = build_agent_report("web-01", {
        "info": {},
        "alerts": [{"source": "Correlation/fleet_spray", "severity": "CRITICAL",
                    "message": "5 distinct hosts saw failures from 203.0.113.77"}],
    })
    assert any(s.title == "Correlation findings" for s in report.sections)


# --------------------------------------------------------------------------
# The fleet report
# --------------------------------------------------------------------------

def test_silent_agents_are_named():
    report = build_fleet_report({
        "agents": [{"name": "a", "status": "Online"},
                   {"name": "b", "status": "Online"}],
        "silent_agents": ["b"],
    })
    assert "sent no telemetry" in _caveats(report)
    assert "b" in " ".join(report.caveats)


def test_no_rules_installed_is_stated_rather_than_shown_as_zero_findings():
    report = build_fleet_report({"agents": [], "covered_techniques": []})
    assert "No detection rules are installed" in " ".join(report.caveats)


def test_techniques_seen_with_no_rule_behind_them_are_called_out():
    """The one state a coverage percentage hides: silence about those means
    nothing at all."""
    report = build_fleet_report({
        "agents": [],
        "covered_techniques": ["T1003.001"],
        "observed_techniques": ["T1003.001", "T1218.011"],
    })
    assert "no rule behind them" in _caveats(report)
    assert "T1218.011" in " ".join(report.caveats)


def test_a_covered_and_quiet_technique_is_not_a_caveat():
    """Normal, and good. Treating it as a warning would bury the real ones."""
    report = build_fleet_report({
        "agents": [],
        "covered_techniques": ["T1003.001", "T1490"],
        "observed_techniques": ["T1003.001"],
    })
    assert "no rule behind" not in _caveats(report)


def test_coverage_distinguishes_three_states():
    report = build_fleet_report({
        "agents": [],
        "covered_techniques": ["T1003.001", "T1490"],
        "observed_techniques": ["T1003.001", "T1218.011"],
    })
    coverage = next(s for s in report.sections if s.title == "ATT&CK coverage")
    states = {row[1] for row in coverage.rows}
    assert "seen, and covered" in states
    assert "covered, never seen" in states
    assert "SEEN WITH NO RULE" in states


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def test_it_renders_a_real_pdf():
    from core.reporting import render_pdf

    report = build_agent_report("web-01", {
        "info": {"os_info": "Ubuntu 24.04", "public_ip": "16.171.42.197"},
        "siem_events": [{"severity": "CRITICAL", "timestamp": "2026-08-27",
                         "rule_title": "LSASS dump", "techniques": "T1003.001",
                         "message": "rundll32 comsvcs MiniDump"}],
        "package_count": 412,
    })
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")


def test_the_caveats_are_rendered_before_the_findings():
    """Buried at the end they are read after the conclusion has been drawn,
    which is when they no longer help."""
    source = (ROOT / "core" / "reporting.py").read_text(encoding="utf-8")
    caveat_at = source.index('"Read this first"')
    sections_at = source.index("for section in report.sections:")
    assert caveat_at < sections_at


def test_a_clean_report_says_so_explicitly():
    """Absence of a warning is not the same as a statement that there is
    nothing to warn about."""
    source = (ROOT / "core" / "reporting.py").read_text(encoding="utf-8")
    assert "read at face value" in source


def test_the_filename_carries_the_timestamp():
    """Two reports for the same host, filed a month apart, must not be the
    same filename."""
    report = Report(title="Security Report - web-01", generated_at="2026-08-27 13:55:50")
    name = filename_for(report)
    assert name.endswith(".pdf")
    assert "2026-08-27" in name
    assert " " not in name


# --------------------------------------------------------------------------
# The endpoints
# --------------------------------------------------------------------------

@pytest.mark.parametrize("handler,route", [
    ("agent_report_pdf", "report.pdf"),
    ("fleet_report_pdf", "fleet.pdf"),
])
def test_the_endpoints_exist_and_are_gated(handler, route):
    fn = _handler(handler)
    decorators = [ast.unparse(d) for d in fn.decorator_list]
    assert any(route in d for d in decorators)
    assert any("require_permission" in d for d in decorators), \
        "a report is an export of telemetry"


@pytest.mark.parametrize("handler", ["agent_report_pdf", "fleet_report_pdf"])
def test_exports_are_audited(handler):
    """A report leaves the platform. Reconstructing who took what, and when,
    is the whole point of an audit trail."""
    body = ast.unparse(_handler(handler))
    assert "audit_log" in body
    assert "EXPORT_REPORT" in body


def test_the_pdf_is_sent_as_an_attachment():
    """Rendered inline, it would run in the API origin's context."""
    body = ast.unparse(_handler("_pdf_response"))
    assert "attachment" in body
    assert "application/pdf" in body


def test_the_report_decrypts_with_the_shared_helper():
    """Not a second implementation. The one app.py used to carry was
    case-sensitive about the `enc::` prefix and silently returned ciphertext,
    which is how the vulnerability scanner asked OSV about a package named
    `enc::gAAAA...`."""
    body = ast.unparse(_handler("_report_rows"))
    assert "telemetry_crypto" in body


def test_the_report_query_quotes_its_table_name():
    body = ast.unparse(_handler("_report_rows"))
    assert "_quote_identifier" in body


def test_rendering_does_not_block_the_event_loop():
    """reportlab is synchronous and a fleet PDF is not instant. Building it on
    the loop would stall every other request for the duration."""
    for handler in ("agent_report_pdf", "fleet_report_pdf"):
        body = ast.unparse(_handler(handler))
        assert "asyncio.to_thread(render_pdf" in body


def test_the_dependency_is_declared():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "reportlab" in requirements
