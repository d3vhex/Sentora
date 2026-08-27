"""Security reports, as PDFs an operator can hand to somebody else.

Two shapes: one host, and the whole estate.

What a report has to do that a console does not
-----------------------------------------------
A console is read by someone who already knows what is missing. A PDF is read
later, by someone who was not there - so every number in it has to carry
whatever qualifies it, or it will be quoted without.

This is not theoretical for this codebase. Three separate things have shipped
here that produced a confident, empty answer:

  - the AI triaged Fernet blobs and wrote fluent summaries of them
  - the vulnerability scanner asked OSV about a package named `enc::gAAAA...`
    and found nothing, for every agent, forever
  - an agent with no local database showed ONLINE with an IP and a hostname
    while sending no telemetry at all

Each looked exactly like good news. So `Report.caveats` is not a footnote
section: it is checked before the findings are believed, and a report with no
findings and no caveats is the only one that means "clean".

Structure
---------
Gathering is separate from rendering. The data can then be asserted on
without generating a PDF, which is most of what is worth testing - and the
rendering has no logic in it worth hiding behind a binary format.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class Section:
    """One block of the report: a heading, some prose, and maybe a table."""

    title: str
    body: str = ""
    columns: tuple[str, ...] = ()
    rows: list[tuple] = field(default_factory=list)
    # Shown instead of an empty table. "No rows" and "nothing was collected"
    # are different claims and a blank space asserts neither.
    empty_note: str = ""


@dataclass
class Report:
    title: str
    subtitle: str = ""
    generated_at: str = ""
    sections: list[Section] = field(default_factory=list)
    # Things that make the numbers above mean less than they appear to.
    caveats: list[str] = field(default_factory=list)

    def add(self, section: Section) -> None:
        self.sections.append(section)

    @property
    def is_trustworthy(self) -> bool:
        """No caveats, so the findings can be read at face value."""
        return not self.caveats


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _severity_key(value: Any) -> int:
    return SEVERITY_ORDER.get(str(value or "").upper(), 9)


def _fmt(value: Any, limit: int = 80) -> str:
    text = str(value if value is not None else "-").replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


# ---------------------------------------------------------------------------
# Per-agent
# ---------------------------------------------------------------------------

def build_agent_report(agent: str, data: dict) -> Report:
    """One host.

    `data` is whatever the caller could gather; every key is optional. A
    section whose data could not be read says so rather than rendering as
    empty, because an operator cannot tell those apart on paper.
    """
    display = data.get("display_name")
    info = data.get("info") or {}

    report = Report(
        title=f"Security Report — {display or agent}",
        subtitle=(f"{agent} · " if display else "")
                 + f"{_fmt(info.get('os_info'), 60) or 'unknown OS'}"
                 + f" · {info.get('public_ip') or 'no address'}",
        generated_at=_now(),
    )

    # ---- posture ----------------------------------------------------------
    last_seen = info.get("last_seen") or "never"
    report.add(Section(
        title="Host",
        body=(f"Last seen {last_seen}. "
              f"Hostname {_fmt(info.get('hostname'), 40)}, "
              f"MAC {_fmt(info.get('mac_address'), 40)}."),
    ))

    if data.get("no_telemetry"):
        report.caveats.append(
            "This agent has sent no telemetry. It appears online because the "
            "address, hostname and MAC arrive in the connection header, which "
            "needs no database on the endpoint - everything below is empty "
            "for that reason and not because the host is quiet.")

    # ---- detections -------------------------------------------------------
    events = sorted(data.get("siem_events") or [],
                    key=lambda r: _severity_key(r.get("severity")))
    notable = [e for e in events
               if str(e.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
    report.add(Section(
        title="Detections",
        body=(f"{len(notable)} event(s) at HIGH or above, out of "
              f"{len(events)} collected."),
        columns=("When", "Severity", "Rule", "Technique", "Event"),
        rows=[(_fmt(e.get("timestamp"), 20), _fmt(e.get("severity"), 10),
               _fmt(e.get("rule_title") or e.get("event_type"), 30),
               _fmt(e.get("techniques"), 20), _fmt(e.get("message"), 70))
              for e in notable[:40]],
        empty_note="Nothing at HIGH or above." if events
                   else "No SIEM events collected from this host.",
    ))

    alerts = data.get("alerts") or []
    correlated = [a for a in alerts
                  if str(a.get("source", "")).startswith("Correlation/")]
    if correlated:
        report.add(Section(
            title="Correlation findings",
            body="Patterns across several events, which no single-event rule "
                 "can express.",
            columns=("When", "Severity", "Technique", "Finding"),
            rows=[(_fmt(a.get("timestamp"), 20), _fmt(a.get("severity"), 10),
                   _fmt(a.get("categories"), 20), _fmt(a.get("message"), 80))
                  for a in correlated[:20]],
        ))

    # ---- vulnerabilities --------------------------------------------------
    vulns = data.get("vulnerabilities") or []
    report.add(Section(
        title="Vulnerabilities",
        body=f"{len(vulns)} finding(s) from the installed package list.",
        columns=("Package", "Version", "ID", "Summary"),
        rows=[(_fmt(v.get("package_name") or v.get("package"), 30),
               _fmt(v.get("package_version") or v.get("version"), 20),
               _fmt(v.get("vulnerability_id"), 22),
               _fmt(v.get("summary"), 60)) for v in vulns[:60]],
        empty_note="No vulnerabilities recorded.",
    ))

    scan_note = data.get("vuln_scan_note")
    if scan_note:
        report.caveats.append(f"Vulnerability scan: {scan_note}")

    packages = data.get("package_count")
    if packages == 0 and not data.get("no_telemetry"):
        report.caveats.append(
            "No installed packages have been collected, so the vulnerability "
            "section is empty for lack of input rather than lack of findings.")

    # ---- AI ---------------------------------------------------------------
    insights = data.get("ai_insights") or []
    surfaced = [i for i in insights
                if str(i.get("source_file", "")).startswith("Realtime_")]
    report.add(Section(
        title="AI triage",
        body=(f"{len(surfaced)} insight(s) were shown to an analyst, out of "
              f"{len(insights)} events triaged."),
        columns=("When", "Verdict", "Severity", "Summary"),
        rows=[(_fmt(i.get("timestamp"), 20), _fmt(i.get("verdict"), 16),
               _fmt(i.get("severity"), 10), _fmt(i.get("critical_summary"), 70))
              for i in surfaced[:25]],
        empty_note="Nothing was escalated to an analyst.",
    ))

    unreadable = sum(1 for i in insights
                     if "could not be decrypted" in str(i.get("critical_summary", "")))
    if unreadable:
        report.caveats.append(
            f"{unreadable} event(s) could not be decrypted and were never "
            f"sent to the model, so the section above understates what "
            f"happened by that many events. The agent is encrypting with a "
            f"key this server does not hold: restart it so it re-fetches "
            f"from /api/agents/bootstrap. Events already stored under the "
            f"old key stay unreadable.")

    return report


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------

def build_fleet_report(data: dict) -> Report:
    """The estate."""
    agents = data.get("agents") or []
    online = [a for a in agents if str(a.get("status", "")).lower() == "online"]

    report = Report(
        title="Fleet Security Report",
        subtitle=f"{len(agents)} agent(s), {len(online)} online",
        generated_at=_now(),
    )

    report.add(Section(
        title="Agents",
        columns=("Agent", "Name", "Status", "Address", "Last seen"),
        rows=[(_fmt(a.get("name"), 28), _fmt(a.get("display_name") or "-", 24),
               _fmt(a.get("status"), 10), _fmt(a.get("public_ip"), 18),
               _fmt(a.get("last_seen"), 20)) for a in agents],
        empty_note="No agents are enrolled.",
    ))

    silent = data.get("silent_agents") or []
    if silent:
        report.caveats.append(
            f"{len(silent)} agent(s) are connected but have sent no telemetry: "
            f"{', '.join(silent[:10])}. They appear online because the "
            f"connection header needs no database on the endpoint.")

    # ---- coverage ---------------------------------------------------------
    covered = set(data.get("covered_techniques") or [])
    observed = set(data.get("observed_techniques") or [])
    blind = observed - covered
    report.add(Section(
        title="ATT&CK coverage",
        body=(f"{len(covered)} technique(s) are addressed by an installed "
              f"rule. {len(observed)} have been seen on this estate."),
        columns=("Technique", "State"),
        rows=([(t, "seen, and covered") for t in sorted(covered & observed)]
              + [(t, "covered, never seen") for t in sorted(covered - observed)][:30]
              + [(t, "SEEN WITH NO RULE") for t in sorted(blind)]),
        empty_note="No detection rules are installed.",
    ))
    if not covered:
        report.caveats.append(
            "No detection rules are installed, so an empty findings section "
            "is a statement about this deployment rather than about the "
            "estate.")
    if blind:
        report.caveats.append(
            f"{len(blind)} technique(s) have been observed with no rule "
            f"behind them: {', '.join(sorted(blind)[:8])}. Silence about "
            f"those means nothing.")

    # ---- findings ---------------------------------------------------------
    findings = data.get("correlation_findings") or []
    report.add(Section(
        title="Cross-host findings",
        body="Patterns spanning several machines, which no single agent can "
             "see.",
        columns=("When", "Severity", "Agent", "Finding"),
        rows=[(_fmt(f.get("timestamp"), 20), _fmt(f.get("severity"), 10),
               _fmt(f.get("agent"), 24), _fmt(f.get("message"), 70))
              for f in findings[:30]],
        empty_note="None recorded.",
    ))

    vulns = data.get("vulnerability_totals") or {}
    report.add(Section(
        title="Vulnerabilities by host",
        columns=("Agent", "Findings"),
        rows=sorted(((_fmt(k, 40), str(v)) for k, v in vulns.items()),
                    key=lambda r: -int(r[1])),
        empty_note="No vulnerabilities recorded on any host.",
    ))

    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_pdf(report: Report) -> bytes:
    """The report as a PDF.

    reportlab rather than an HTML engine: WeasyPrint and friends need cairo
    and pango, which is a large amount of system library in a container that
    otherwise needs none.
    """
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                    SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=report.title, author="Sentora",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18,
                        spaceAfter=2, textColor=colors.HexColor("#111111"))
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=9,
                         textColor=colors.HexColor("#666666"), spaceAfter=12)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12,
                        spaceBefore=14, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9,
                          leading=13, alignment=TA_LEFT)
    note = ParagraphStyle("note", parent=body, textColor=colors.HexColor("#777777"),
                          fontSize=8.5)
    warn = ParagraphStyle("warn", parent=body, fontSize=9,
                          textColor=colors.HexColor("#8a2b06"), leading=13,
                          spaceAfter=4)

    story: list = [Paragraph(report.title, h1),
                   Paragraph(f"{report.subtitle} · generated {report.generated_at}", sub)]

    # Caveats first. Buried at the end they are read after the conclusion has
    # already been drawn, which is exactly when they no longer help.
    if report.caveats:
        story.append(Paragraph("Read this first", h2))
        story.append(Paragraph(
            "The findings below are incomplete in ways that matter:", body))
        story.append(Spacer(1, 4))
        for caveat in report.caveats:
            story.append(Paragraph(f"• {caveat}", warn))
    else:
        story.append(Paragraph(
            "No collection gaps were detected, so the findings below can be "
            "read at face value.", note))

    for section in report.sections:
        block: list = [Paragraph(section.title, h2)]
        if section.body:
            block.append(Paragraph(section.body, body))
        block.append(Spacer(1, 4))

        if section.rows:
            data_rows = [list(section.columns)] + [list(r) for r in section.rows]
            table = Table(data_rows, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#fafafa")]),
            ]))
            block.append(table)
        elif section.empty_note:
            block.append(Paragraph(section.empty_note, note))

        # Heading and its first rows stay together; a heading alone at the
        # foot of a page reads as an empty section.
        story.append(KeepTogether(block[:2]) if len(block) > 1 else block[0])
        story.extend(block[2:])

    def _footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#999999"))
        canvas.drawString(18 * mm, 10 * mm,
                          f"Sentora · {report.title} · {report.generated_at}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def filename_for(report: Report) -> str:
    """A filename that sorts and does not need quoting."""
    import re

    stem = re.sub(r"[^A-Za-z0-9]+", "-", report.title).strip("-").lower()
    stamp = report.generated_at.replace(":", "").replace(" ", "-")
    return f"{stem}-{stamp}.pdf"
