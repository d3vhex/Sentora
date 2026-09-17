"""The Assets tabs must render columns the served table actually has.

A cell bound to a column that does not exist renders as empty, and an empty
cell reads as a fact about the host: "this machine reports no vendor". Nothing
anywhere says otherwise - not the API, which returns the rows it was asked for,
not the agent, which collected the vendor and shipped it, not the console,
which draws what it was given.

It has happened twice on this page:

  - the Network tab had a `Protocol` column that `network_connections` has no
    field for, while the remote address - the whole point of an established
    connection - was not shown at all;
  - the Software tab rendered Vendor and Installed Date out of `packages`,
    which holds a name and a version. The agent had been collecting both into
    `software_inventory` and shipping it to a table nothing read.

Both were found by looking at the screen, which is the expensive way. This
checks the tabs against the schema instead.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASSETS = ROOT / "frontend" / "src" / "pages" / "Assets.tsx"
APP = ROOT / "app.py"
SCHEMA = ROOT / "db" / "init.sql"

TABS = ("hardware", "software", "network")

#: Keys the API adds or the page derives, which no table is expected to hold.
NOT_FROM_THE_TABLE: set = set()


def _without_comments(source: str) -> str:
    """Drop `{/* ... */}` and `// ...`.

    Not fussiness: a check of this shape has passed over broken code twice in
    this repository by matching the prose in a comment that described the very
    thing that was missing.
    """
    source = re.sub(r"\{/\*.*?\*/\}", "", source, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", source)


def _tab_fields(tab: str) -> set:
    """Every `item.<field>` rendered while this tab is active."""
    source = _without_comments(ASSETS.read_text(encoding="utf-8"))
    marker = f"activeTab === '{tab}' && <>"
    fields: set = set()
    start = source.find(marker)
    assert start != -1, f"the {tab} tab no longer renders a block of its own"
    while start != -1:
        end = source.find("</>}", start)
        assert end != -1, f"unterminated {tab} block in Assets.tsx"
        fields |= set(re.findall(r"\bitem\.(\w+)", source[start:end]))
        start = source.find(marker, end)
    return fields - NOT_FROM_THE_TABLE


def _served_table(tab: str) -> tuple:
    """(table, rename_map) for the route the tab fetches.

    Read out of app.py rather than restated here - the point is to catch the
    two drifting apart, which a second copy of the answer cannot do.
    """
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    wanted = f"/api/agent/<agent>/inventory/{tab}"

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routes = [
            d.args[0].value
            for d in node.decorator_list
            if isinstance(d, ast.Call) and d.args
            and isinstance(d.args[0], ast.Constant)
            and isinstance(d.args[0].value, str)
        ]
        if wanted not in routes:
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            name = getattr(func, "id", None) or getattr(func, "attr", "")
            if not name.startswith("stream_from_db"):
                continue
            table = call.args[0].value
            renames = {}
            for kw in call.keywords:
                if kw.arg == "rename_map" and isinstance(kw.value, ast.Dict):
                    renames = {k.value: v.value
                               for k, v in zip(kw.value.keys, kw.value.values)}
            return table, renames
    raise AssertionError(f"no route serves {wanted}")


def _columns(table: str) -> set:
    """Column names from the server-side schema - the database the API reads."""
    sql = SCHEMA.read_text(encoding="utf-8")
    match = re.search(
        r"CREATE TABLE IF NOT EXISTS\s+`?" + re.escape(table) + r"`?\s*\((.*?)\n\)",
        sql, re.S)
    assert match, f"{table} is not created by db/init.sql"

    columns = set()
    for line in match.group(1).splitlines():
        line = line.split("--")[0].strip()
        if not line or line.upper().startswith(("KEY ", "UNIQUE ", "PRIMARY ",
                                                "INDEX ", "CONSTRAINT ")):
            continue
        name = line.split()[0].strip("`,")
        if name:
            columns.add(name)
    return columns


@pytest.mark.parametrize("tab", TABS)
def test_every_rendered_column_exists(tab):
    table, renames = _served_table(tab)
    available = {renames.get(c, c) for c in _columns(table)}
    rendered = _tab_fields(tab)

    missing = sorted(rendered - available)
    assert not missing, (
        f"the {tab} tab renders {missing} from `{table}`, which has no such "
        f"column. The cells are blank and read as the host having nothing to "
        f"report."
    )


@pytest.mark.parametrize("tab", TABS)
def test_the_tab_renders_something(tab):
    """A guard on the parser above, not on the page. If the block markers in
    Assets.tsx change shape, `_tab_fields` returns an empty set and the check
    passes while testing nothing."""
    assert _tab_fields(tab), f"no item fields found for the {tab} tab"


def test_the_software_tab_reads_the_inventory_not_the_scanner_input():
    """`packages` is the vulnerability scanner's input: encrypted, shaped for
    OSV, name and version only. It was serving this page for want of anyone
    noticing the empty columns."""
    table, _ = _served_table("software")
    assert table == "software_inventory", (
        f"the Software tab is served from `{table}`; the vendor and install "
        f"date it renders only exist in software_inventory."
    )
