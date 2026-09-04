"""The console has one vocabulary, and pages use it rather than reinventing it.

There were 1291 inline style objects across 24 pages, and `StatCard` had been
written three separate times - on Dashboard, ThreatIntel and AttackCoverage -
which had drifted to different paddings, weights and label sizes.

None of those pages was written carelessly. The problem is that there was no
shared vocabulary to be careless *about*: spacing, radius and colour were
decided again on every page, and independently made decisions diverge. That is
why the console looked like three products.

These tests do not try to eliminate inline styles - a page will always have
some, and a rule against them would be gamed rather than followed. They pin
the things that actually caused the drift: one definition of each primitive,
one radius scale, and no page inventing a component that already exists.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend" / "src"
UI = FRONTEND / "components" / "ui" / "index.tsx"
CSS = FRONTEND / "index.css"

PAGES = sorted((FRONTEND / "pages").glob("*.tsx"))


def test_the_primitives_exist():
    source = UI.read_text(encoding="utf-8")
    for name in ("PageHeader", "Card", "StatCard", "DataTable",
                 "EmptyState", "ErrorState", "LoadingState", "Badge"):
        assert f"export function {name}" in source, name


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_no_page_defines_its_own_statcard(page):
    """It was defined three times. Each copy looked reasonable; together they
    made one number mean three different things visually."""
    source = page.read_text(encoding="utf-8")
    assert "const StatCard" not in source, (
        f"{page.name} defines its own StatCard - import it from components/ui"
    )
    assert "function StatCard" not in source, page.name


def test_the_shared_statcard_is_actually_used():
    """A primitive nothing imports is a primitive that will drift back out."""
    users = [p.name for p in PAGES
             if "from '../components/ui'" in p.read_text(encoding="utf-8")]
    assert users, "nothing imports the shared components"


# --------------------------------------------------------------------------
# The tokens
# --------------------------------------------------------------------------

def _tokens() -> dict:
    css = CSS.read_text(encoding="utf-8")
    block = css[css.index(":root {"):css.index("\n}", css.index(":root {"))]
    return dict(re.findall(r"(--[\w-]+):\s*([^;]+);", block))


@pytest.mark.parametrize("name", [
    "--space-1", "--space-4", "--space-6",
    "--text-xs", "--text-base", "--text-2xl",
    "--radius-sm", "--radius-md",
    "--sev-critical", "--sev-high", "--sev-medium", "--sev-low",
    "--chart-1", "--chart-2", "--chart-grid",
])
def test_the_scale_exists(name):
    """Spacing and type as scales, so vertical rhythm is a choice made once
    instead of 28px here and 24px three lines down."""
    assert name in _tokens(), f"{name} is not defined"


def test_the_radius_scale_is_small():
    """The old set had 12px cards next to 4px inputs, which is most of why the
    console read as a toy rather than a tool. One small scale, applied
    everywhere."""
    tokens = _tokens()
    for name in ("--radius-sm", "--radius-md", "--radius-lg"):
        pixels = int(re.sub(r"\D", "", tokens[name]))
        assert pixels <= 8, f"{name} is {pixels}px"


def test_there_is_a_chart_palette_separate_from_the_semantic_one():
    """A bar being red should not imply danger unless danger is what the bar
    measures. Reusing the severity colours for series is how a chart starts
    lying about its own data."""
    tokens = _tokens()
    series = {tokens[f"--chart-{i}"].strip().lower() for i in range(1, 7)}
    severity = {tokens[n].strip().lower() for n in
                ("--sev-critical", "--sev-high", "--sev-medium")}
    assert not (series & severity), \
        f"chart series reuse severity colours: {sorted(series & severity)}"


# --------------------------------------------------------------------------
# Affordances a data console should not have
# --------------------------------------------------------------------------

def _card_rule() -> str:
    """The top-level `.card` rule.

    Matched at the start of a line: there is a `.card` override inside a
    media query too, and slicing from the first occurrence lands in it and
    then spans half the stylesheet - which made this test read `button:active
    { transform: ... }` as a card that moves.
    """
    css = CSS.read_text(encoding="utf-8")
    match = re.search(r"^\.card \{(.*?)^\}", css, re.M | re.S)
    assert match, "no top-level .card rule"
    return match.group(1)


def test_cards_do_not_move_when_you_point_at_them():
    """`.card:hover` lifted two pixels and glowed. On a page that is mostly
    cards, the whole console moves when the pointer crosses it - which reads
    as a toy, and on a dense table view is genuinely distracting. A card is
    where data sits; it is not a button.

    Pages opt into `.card--interactive` where a card really is a control.
    """
    css = CSS.read_text(encoding="utf-8")
    assert not re.search(r"^\.card:hover", css, re.M), \
        "the card itself reacts to the pointer again"
    assert ".card--interactive:hover" in css, \
        "nothing is left for a card that genuinely is a control"


def test_cards_do_not_blur_what_is_behind_them():
    """A 12px backdrop blur on every card, repainting on every scroll, to
    produce an effect invisible against a black ground."""
    assert "backdrop-filter" not in _card_rule()


# --------------------------------------------------------------------------
# Pages that exist have to be reachable
# --------------------------------------------------------------------------

def test_every_page_is_routed():
    """A page nobody can navigate to is a page nobody will find. The chain
    view shipped with an endpoint and a component and no way in, which is
    indistinguishable from not having built it."""
    app = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    unrouted = []
    for page in PAGES:
        if page.stem in ("Login",):
            continue
        if f"pages/{page.stem}'" not in app:
            unrouted.append(page.stem)
    assert not unrouted, f"pages with no route: {unrouted}"


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------

CHARTS = FRONTEND / "components" / "ui" / "charts.tsx"


def test_the_chart_library_is_declared():
    """`import 'recharts'` with nothing in package.json is a build that fails
    on someone else's machine."""
    package = (ROOT / "frontend" / "package.json").read_text(encoding="utf-8")
    assert '"recharts"' in package


def test_charts_read_the_theme_rather_than_carrying_their_own():
    """Recharts styles itself with props, not CSS, so left alone it draws a
    white grid and a light tooltip on a black page. If the wrappers stop
    reading tokens the charts stop matching the console and nothing fails."""
    source = CHARTS.read_text(encoding="utf-8")
    assert "var(--chart-1)" in source
    assert "var(--chart-grid)" in source
    assert "var(--surface-2)" in source


def test_series_colours_are_not_the_severity_colours():
    """A bar being red should not imply danger unless danger is what the bar
    measures."""
    source = CHARTS.read_text(encoding="utf-8")
    series_block = source[source.index("export const SERIES"):
                          source.index("const axis")]
    assert "--sev-" not in series_block


def test_an_empty_chart_says_it_is_empty():
    """An empty chart and a chart that failed to load are the same picture,
    and on a security console the difference is whether you are safe or
    blind."""
    source = CHARTS.read_text(encoding="utf-8")
    assert "EmptyState" in source
    assert "not a loading state" in source


def test_the_trend_draws_both_counts():
    """A thousand detections from one noisy rule and a thousand from forty
    techniques are the same bar and completely different days. Only the two
    together separate them."""
    source = CHARTS.read_text(encoding="utf-8")
    trend = source[source.index("export function TrendChart"):
                   source.index("export function ShareDonut")]
    assert "detections" in trend
    assert "distinct" in trend
    assert 'yAxisId="right"' in trend, "both series are on one axis"


def test_the_trend_endpoint_fills_the_quiet_days():
    """A line drawn only through the days that had events invents a slope
    between them, and a two-day gap reads as a gradual decline."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    body = app_py[app_py.index("def _threat_trend"):
                  app_py.index("@app.route(\"/threat-trend\")")]
    assert "timedelta" in body
    assert "range(days" in body


def test_the_dashboard_says_whether_a_command_would_reach_a_host():
    """Telemetry and control travel on different connections, so an agent can
    be reporting and be uncommandable - and the console has been unable to
    say which since the HTTP fallback went."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '"channel_connected"' in app_py

    dashboard = (FRONTEND / "pages" / "Dashboard.tsx").read_text(encoding="utf-8")
    assert "channel_connected" in dashboard


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_no_page_reaches_past_the_chart_wrappers(page):
    """Recharts styles itself with props, not CSS. A page importing it
    directly draws a white grid and a light tooltip on a black ground, and
    picks its own series colours - which is how the console came to look like
    three products the first time."""
    source = page.read_text(encoding="utf-8")
    assert "from 'recharts'" not in source, (
        f"{page.name} imports recharts directly; use components/ui/charts so "
        f"the palette and the axes stay in one place"
    )


def test_the_charted_pages_use_the_shared_palette():
    """A chart is only consistent if its colours come from the tokens. Pages
    that hardcode a hex are how a series colour comes to mean two things."""
    charted = [p for p in PAGES
               if "components/ui/charts" in p.read_text(encoding="utf-8")]
    assert len(charted) >= 4, (
        f"only {len(charted)} pages use the shared charts; the dashboard's "
        f"visual language has not reached the rest of the console"
    )


#: Pages whose data is a distribution rather than a record. A table is the
#: right way to read one row; it is the wrong way to see that four hundred of
#: them are the same package, or that every failure belongs to one playbook.
CHART_WORTHY = [
    "Dashboard", "GlobalAlerts", "Agents", "AttackCoverage",
    "FileIntegrity", "SoarHub", "ThreatIntel", "AgentDetail",
    "Assets", "AuditLogs", "LoginLogs",
]


@pytest.mark.parametrize("stem", CHART_WORTHY)
def test_the_pages_that_answer_a_distribution_draw_one(stem):
    """The console had exactly one page with charts and twenty-three with
    tables, so the dashboard looked like a different product from everything
    it linked to. This is the list of pages where the shape of the data is
    the answer, not a decoration on it."""
    page = FRONTEND / "pages" / f"{stem}.tsx"
    source = page.read_text(encoding="utf-8")
    assert "components/ui/charts" in source, (
        f"{stem} answers a 'how much of what' question and still only has a "
        f"table"
    )


@pytest.mark.parametrize("stem", CHART_WORTHY)
def test_the_chart_import_is_actually_rendered(stem):
    """Importing a wrapper and never rendering it makes the page pass the
    test above while looking exactly as it did before. Grep for the import is
    not evidence of a chart; a `data=` prop on a wrapper is."""
    source = (FRONTEND / "pages" / f"{stem}.tsx").read_text(encoding="utf-8")
    wrappers = ("CategoryBars", "ShareDonut", "TrendChart", "SeriesLines")
    rendered = [w for w in wrappers if re.search(rf"<{w}", source)]
    assert rendered, f"{stem} imports the chart wrappers but renders none"

    for wrapper in rendered:
        assert re.search(rf"<{wrapper}[^>]*data=", source, re.S), (
            f"{stem} renders <{wrapper}> with no data prop"
        )


def test_the_wrappers_let_a_caller_colour_a_state():
    """Most series should take the neutral palette. But when the category *is*
    a severity or an outcome, drawing "failed" in whatever colour the third
    slice happened to get is the chart lying about its own data."""
    source = CHARTS.read_text(encoding="utf-8")
    for wrapper in ("CategoryBars", "ShareDonut"):
        block = source[source.index(f"export function {wrapper}"):]
        block = block[:block.index(chr(10) + "}" + chr(10))]
        assert "colorFor" in block, f"{wrapper} cannot express a semantic colour"


def test_the_line_chart_pins_its_axis():
    """A percentage axis that rescales to its data draws 4% and 40% as the
    same picture, which is the one thing a resource chart must not do."""
    source = CHARTS.read_text(encoding="utf-8")
    lines = source[source.index("export function SeriesLines"):
                   source.index("export function ShareDonut")]
    assert "domain ?? [0, 100]" in lines


def test_the_attack_chain_is_reachable_from_a_host():
    """It answers a question about one machine, so it is reached from that
    machine rather than from the nav."""
    app = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    assert "/agent/:agentName/chain" in app

    detail = (FRONTEND / "pages" / "AgentDetail.tsx").read_text(encoding="utf-8")
    assert "/chain" in detail, "no link into the chain view from the host page"
