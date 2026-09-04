"""Search could not answer the question anybody actually has.

It was free text across every field, over the whole retention, first N
results, with no way to reach the N+1th. So "what happened on that host
between two and four, with severity critical" could not be asked at all - not
because the data was missing, but because the query had nowhere to put a time,
a field, or a page.

Three defects underneath that were their own bugs:

    limit = int(request.args.get("limit", 100))

`?limit=abc` raised inside the handler and came back as a bodyless 500;
`?limit=999999` was honoured and sent straight to OpenSearch.

    {"wildcard": {"agent_name": agent}}

The caller's string went into a `wildcard` clause. The default was `*`, so
every search matched every term in the index, and a leading `*` was one
keystroke away from a scan of every term there is.

    resp = os_utils.search_logs(...)
    if not resp: return sanic_json({"hits": []})

`search_logs` caught everything and returned None, so a malformed query, an
unreachable OpenSearch and a genuinely empty result were the same screen. On a
security console the difference between "no matches" and "the search did not
run" is the difference between an all-clear and no answer at all.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
OS_UTILS = ROOT / "core" / "opensearch.py"
PAGE = ROOT / "frontend" / "src" / "pages" / "Search.tsx"


def _function(path: pathlib.Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(ast.unparse(n) for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


def _compiled(path: pathlib.Path, name: str, extra: dict | None = None):
    """One function, compiled with the module constants it refers to.

    Compiling the function alone raises NameError the moment it uses a
    module-level constant - which reads as a bug in the code rather than in
    the harness. The constants it names are lifted with it.
    """
    import re as _re

    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    referenced = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    constants = [n for n in tree.body
                 if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in referenced for t in n.targets)]

    namespace: dict = {"re": _re, "datetime": __import__("datetime").datetime}
    namespace.update(extra or {})
    exec(compile(ast.Module(body=[*constants, fn], type_ignores=[]),
                 str(path), "exec"), namespace)
    return namespace[name]


# --------------------------------------------------------------------------
# A bounded page size
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (None, 50), ("", 50), ("abc", 50), ("-4", 1), ("0", 1),
    ("20", 20), ("999999", 200),
])
def test_a_page_size_is_bounded_and_never_raises(raw, expected):
    """`int(request.args.get("limit", 100))` turned `?limit=abc` into a
    bodyless 500 and honoured `?limit=999999`."""
    positive_int = _compiled(APP, "_positive_int")
    assert positive_int(raw, 50, 200) == expected


# --------------------------------------------------------------------------
# A window, which there was none of
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["now-1h", "now-7d", "now", "now-1d/d"])
def test_relative_windows_are_accepted(raw):
    bound = _compiled(APP, "_time_bound")
    assert bound(raw, "now-24h") == raw


def test_an_absolute_timestamp_is_accepted():
    bound = _compiled(APP, "_time_bound")
    assert bound("2026-09-01T12:00:00", "now-24h") == "2026-09-01T12:00:00"


@pytest.mark.parametrize("raw", [
    "yesterday", "now-", "'; DROP", "now-1x", "", None,
])
def test_junk_falls_back_rather_than_reaching_the_engine(raw):
    """An unparseable bound sent through comes back as a 400 the operator has
    to decode."""
    bound = _compiled(APP, "_time_bound")
    assert bound(raw, "now-24h") == "now-24h"


def test_there_is_a_default_window_at_all():
    """The single biggest change. With no time filter every search scanned the
    whole retention and sorted it, and the question an operator has is nearly
    always about a window."""
    code = _function(APP, "search_logs_api")
    assert "SEARCH_DEFAULT_WINDOW" in code
    assert '"range"' in code or "'range'" in code


# --------------------------------------------------------------------------
# The query
# --------------------------------------------------------------------------

def test_the_query_is_field_aware():
    """`multi_match` across `fields: ["*"]` cannot express `severity:critical`,
    which is the first thing anybody wants to type."""
    code = _function(APP, "search_logs_api")
    assert "query_string" in code
    assert "multi_match" not in code


def test_a_leading_wildcard_is_refused():
    """`*foo` forces a scan of every term in the index. It is the classic way
    to take a search cluster down from a text box."""
    code = _function(APP, "search_logs_api")
    assert "'allow_leading_wildcard': False" in code \
        or '"allow_leading_wildcard": False' in code


def test_the_agent_filter_is_a_term_not_a_wildcard():
    """The caller's string went straight into a `wildcard` clause, and the
    default was `*`."""
    code = _function(APP, "search_logs_api")
    # The clause, not the word: `analyze_wildcard` and
    # `allow_leading_wildcard` are settings on the query parser and both
    # legitimately contain it.
    assert "'wildcard':" not in code and '"wildcard":' not in code, \
        "the caller's string is back in a wildcard clause"
    assert "terms" in code
    assert "_agent_name_forms" in code, \
        "a hyphenated host would not be found under the console's spelling"


# --------------------------------------------------------------------------
# Results you can get past the first page of
# --------------------------------------------------------------------------

def test_results_are_paged():
    code = _function(APP, "search_logs_api")
    assert "'from'" in code or '"from"' in code
    assert "pages" in code
    assert "track_total_hits" in code, "the total is capped at 10000 without it"


# --------------------------------------------------------------------------
# A failed search is not an empty one
# --------------------------------------------------------------------------

def test_the_engine_reports_failures_instead_of_swallowing_them():
    source = OS_UTILS.read_text(encoding="utf-8")
    assert "class SearchError" in source
    body = _function(OS_UTILS, "search_logs")
    assert "raise SearchError" in body
    assert "return None" not in body


def test_a_broken_query_is_a_400_with_the_reason():
    """Not `{"hits": []}`. A search that could not run and a search that found
    nothing were the same screen."""
    code = _function(APP, "search_logs_api")
    assert "SearchError" in code
    assert "400" in code
    assert "could not be run" in code


def test_the_page_tells_the_two_apart():
    page = PAGE.read_text(encoding="utf-8")
    assert "The search did not run" in page
    assert "No matches in this window" in page


# --------------------------------------------------------------------------
# Two stores, two tabs
# --------------------------------------------------------------------------

def test_events_are_searched_separately():
    """One ranking over both would have to decide whether a raw log line
    outranks a detection, and there is no answer to that."""
    source = APP.read_text(encoding="utf-8")
    assert '"/api/events/search"' in source
    page = PAGE.read_text(encoding="utf-8")
    assert "'logs'" in page and "'events'" in page


def test_event_columns_are_an_allowlist():
    """They become SQL identifiers. Everything the operator types goes in as a
    parameter; only the column comes from here."""
    source = APP.read_text(encoding="utf-8")
    assert "EVENT_SEARCH_TABLES" in source
    code = _function(APP, "search_events_api")
    assert "not searchable" in code


def test_events_are_matched_after_decryption():
    """The searchable text is inside the ciphertext, so a `LIKE` in SQL
    matches nothing and reports it as no results - which is the failure this
    page is being rebuilt around."""
    code = _function(APP, "_search_events_sync")
    assert "decrypt_row_fields" in code
    assert "LIKE" not in code.upper()


# --------------------------------------------------------------------------
# The console
# --------------------------------------------------------------------------

def test_the_filters_and_the_text_are_the_same_thing():
    """A builder that hides the query teaches nothing, and a bare text box
    helps nobody on their first day."""
    page = PAGE.read_text(encoding="utf-8")
    assert "function toQuery" in page
    assert "setQuery(toQuery(next))" in page


def test_a_result_value_can_be_clicked_to_narrow():
    """How a search becomes an investigation rather than one question."""
    page = PAGE.read_text(encoding="utf-8")
    assert "addFilter(col, hit[col])" in page


def test_a_result_links_to_its_host():
    page = PAGE.read_text(encoding="utf-8")
    assert "/agent/${encodeURIComponent(agentOf(hit))}" in page


def test_the_old_path_still_lands_somewhere():
    """A bookmark to /log-search should not fall through to the dashboard
    catch-all, which looks like the page was deleted."""
    app_tsx = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert '/log-search' in app_tsx
    assert 'Navigate to="/search"' in app_tsx
