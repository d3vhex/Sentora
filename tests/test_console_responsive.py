"""The console has to work on a narrow screen, and an inline style cannot.

The shared kit says this in its own docstring — "responsiveness lives here
rather than in each page; a page that lays itself out cannot be made responsive
twenty times" — and six pages had done it anyway, because a two-column layout
is three words of `gridTemplateColumns` and the breakpoint it needs is not
expressible there at all.

The result was not a page that degraded. It was two columns at 400px wide, with
the sidebar and the table each too narrow to read and the body scrolling
sideways.

One of them was worse than a fixed layout:

    gridTemplateColumns: window.innerWidth > 768 ? '1fr 1fr' : '1fr'

That reads the width once, while React renders. Resizing changes nothing —
nothing tells the component to render again — so the layout is whatever the
window happened to be when the tab was opened. It passes a test done by
reloading at each size, and fails the one done by dragging the window.
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGES = ROOT / "frontend" / "src" / "pages"
CSS = ROOT / "frontend" / "src" / "index.css"

PAGE_FILES = sorted(PAGES.glob("*.tsx"))


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?<!:)//[^\n]*")


def _source(path: pathlib.Path) -> str:
    """The file with its comments removed.

    Every one of these checks is about what the code does, and every fix here
    left a comment explaining the thing it replaced — so a scanner that reads
    comments finds `window.innerWidth` in the paragraph that says why
    `window.innerWidth` is gone, and reports the fix as the bug.

    The `(?<!:)` on the line-comment pattern keeps `https://` intact; without
    it a URL in a string truncates the rest of the line and can hide a real
    match after it.
    """
    text = path.read_text(encoding="utf-8")
    text = _BLOCK_COMMENT.sub(" ", text)
    return _LINE_COMMENT.sub(" ", text)


def test_there_are_pages_to_check():
    assert PAGE_FILES, "no pages found — the glob is wrong, not the console"


COMPONENTS = sorted((ROOT / "frontend" / "src" / "components").glob("*.tsx"))


@pytest.mark.parametrize("path", PAGE_FILES + COMPONENTS, ids=lambda p: p.name)
def test_window_width_is_only_read_by_something_that_listens_for_resize(path):
    """Reading the width is not the bug. Reading it *without subscribing to
    changes* is.

    `Layout` reads it for its initial state and registers a `resize` listener,
    which is the correct shape and stays. `Sidebar` read it inside a style
    object and was right only by accident — `Layout` re-renders it on every
    change, so the moment that stopped being true the sidebar would have been
    fixed-positioned on a desktop with nothing to explain it. It takes the
    answer as a prop now.

    `AgentDetail` had two, and both were simply wrong: nothing re-rendered
    them, so the layout was whatever the window happened to be when the tab
    was opened.
    """
    src = _source(path)
    if "window.innerWidth" not in src:
        return
    assert "addEventListener('resize'" in src or 'addEventListener("resize"' in src, (
        f"{path.name} reads window.innerWidth and never listens for resize, so "
        f"the value is sampled once per render and the layout never follows "
        f"the window. Use a CSS breakpoint, or take the answer from a "
        f"component that does listen."
    )


@pytest.mark.parametrize("page", PAGE_FILES, ids=lambda p: p.name)
def test_no_page_hardcodes_a_multi_column_grid(page):
    """`auto-fit` is allowed: it collapses on its own. An explicit column list
    is not, because there is no way to change it below a breakpoint from an
    inline style — that is what `.split-grid` and `.responsive-grid` are for."""
    src = _source(page)
    offenders = []
    for match in re.finditer(r"gridTemplateColumns:\s*'([^']+)'", src):
        value = match.group(1)
        if "auto-fit" in value or "auto-fill" in value:
            continue
        # A single column cannot break; it is already the narrow layout.
        if value.strip() in ("1fr", "100%"):
            continue
        offenders.append(value)
    assert not offenders, (
        f"{page.name} hardcodes {offenders}. Two columns stay two columns on a "
        f"phone — use className=\"split-grid\" (main + aside) or "
        f"\"responsive-grid\" (equal cards), both of which carry a breakpoint."
    )


def test_the_kit_provides_what_the_pages_need():
    """A rule the pages cannot follow is a rule that gets broken. Both classes
    have to exist, and both have to collapse."""
    css = _source(CSS)
    for cls in (".split-grid", ".responsive-grid"):
        assert cls in css, f"{cls} is missing from index.css"

    # The collapse is the whole point; a split-grid without a media query is
    # the inline style again, moved.
    assert re.search(r"@media[^{]*max-width[^{]*\{[^}]*\.split-grid", css, re.S), (
        "`.split-grid` has no max-width media query, so it never collapses"
    )


def test_a_form_control_can_shrink(page=None):
    """`width: '300px'` on an input is 300px on a 360px phone, plus padding,
    plus whatever is beside it. `maxWidth` gives the same look on a desktop and
    fits on a phone."""
    offenders = []
    for path in PAGE_FILES:
        src = _source(path)
        for match in re.finditer(r"width:\s*'(\d{3,})px'", src):
            # `maxWidth:` and `minWidth:` match the same pattern; look at what
            # precedes to tell them apart.
            preceding = src[max(0, match.start() - 4):match.start()]
            if preceding.endswith(("max", "min")):
                continue
            # A width on a table cell is a hint the layout algorithm is free
            # to ignore, and these tables already scroll inside their own
            # container. It is not the same thing as a control that cannot
            # shrink below its declared width.
            #
            # The enclosing *element*, not the enclosing line. A style object
            # spanning several lines puts the tag out of sight, and the
            # line-based version of this went green the moment a `<td>` was
            # reformatted onto its own line — which is the same "looks fine,
            # checks nothing" failure the whole file exists to catch. It was
            # caught here by reformatting one.
            opening = src.rfind("<", 0, match.start())
            tag = src[opening:opening + 4] if opening != -1 else ""
            if tag.startswith(("<td", "<th")):
                continue
            offenders.append(f"{path.name}: width {match.group(1)}px")
    assert not offenders, (
        "fixed widths that cannot shrink: " + ", ".join(offenders)
        + ". Use maxWidth with width: '100%'."
    )


def test_wide_content_scrolls_inside_itself():
    """The kit's `DataTable` wraps in `.table-responsive`. A page writing its
    own `<table>` has to do the same, or the whole body scrolls sideways and
    the sidebar drifts with it."""
    css = _source(CSS)
    assert ".table-responsive" in css

    offenders = []
    for path in PAGE_FILES:
        src = _source(path)
        tables = src.count("<table")
        wrappers = src.count("overflowX") + src.count("table-responsive")
        if tables > wrappers:
            offenders.append(f"{path.name} ({tables} tables, {wrappers} wrappers)")
    # AuditLogs' third table is a two-column label/value list inside a dialog
    # that scrolls vertically, with `wordBreak: break-all` on the value - it has
    # nothing to scroll sideways.
    offenders = [o for o in offenders if not o.startswith("AuditLogs.tsx")]
    assert not offenders, f"tables with no scroll container: {offenders}"
