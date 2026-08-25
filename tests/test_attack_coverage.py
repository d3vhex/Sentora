"""ATT&CK coverage: what the platform can detect, and what it has seen.

Two numbers that are easily confused and are not the same thing.

`covered` is capability - techniques some installed Sigma rule addresses.
`observed` is history - techniques that have actually fired here. A technique
can be covered and never observed, which is the normal case and not a problem.

The cell that matters is the third one: neither covered nor observed. Nothing
installed would have caught it, so its absence from the console is not
evidence of anything. A coverage view that does not separate "quiet" from
"blind" tells an operator they are safe when what they are is unaware, which
is the failure this endpoint exists to prevent.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = (ROOT / "app.py").read_text(encoding="utf-8")
TREE = ast.parse(APP)


def _handler(name):
    return next(n for n in ast.walk(TREE)
                if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
                and n.name == name)


def _returns_keys(name: str) -> set[str]:
    """The keys of the dict the handler returns.

    Read from the AST rather than by searching the source: `ast.unparse`
    normalises quotes, so a text search for a double-quoted key finds nothing
    and the test fails on formatting rather than on behaviour.
    """
    keys = set()
    for node in ast.walk(_handler(name)):
        if isinstance(node, ast.Dict):
            keys.update(k.value for k in node.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str))
    return keys


def test_the_endpoint_exists_and_is_gated():
    fn = _handler("get_attack_coverage")
    decorators = [ast.unparse(d) for d in fn.decorator_list]
    assert any("attack/coverage" in d for d in decorators)
    assert any("require_permission" in d for d in decorators)


def test_it_reports_capability_and_history_separately():
    keys = _returns_keys("get_attack_coverage")
    assert "covered" in keys
    assert "observed" in keys


def test_it_names_the_blind_spot():
    """Covered-but-quiet and seen-but-uncovered are different states and a
    single "coverage %" hides both."""
    keys = _returns_keys("get_attack_coverage")
    assert "quiet" in keys
    assert "uncovered_but_seen" in keys


def test_coverage_is_read_from_the_rules_the_agent_loads():
    """Otherwise the console can claim a technique is covered while no
    installed rule detects it - the worst possible direction for this
    particular number to be wrong in."""
    body = ast.unparse(_handler("_sigma_technique_index"))
    assert "SIGMA_RULES_PATH" in body
    assert "load_dir" in body


def test_a_database_without_the_column_is_skipped_not_fatal():
    """An agent enrolled before `techniques` existed must not fail the whole
    request for every other agent."""
    body = ast.unparse(_handler("get_attack_coverage"))
    assert "continue" in body


def test_the_query_quotes_its_identifiers():
    body = ast.unparse(_handler("get_attack_coverage"))
    assert "_quote_identifier" in body


# --------------------------------------------------------------------------
# The technique index itself
# --------------------------------------------------------------------------

def test_techniques_come_from_the_rules_not_a_table(tmp_path, monkeypatch):
    """Sigma rules carry `tags: attack.t1059`, so there is no mapping table
    to write or keep current - which is most of why Sigma is worth the work."""
    from core import sigma_loader

    (tmp_path / "a.yml").write_text("""
title: one
logsource: {product: windows}
detection:
    selection: {Image: 'x.exe'}
    condition: selection
tags: [attack.execution, attack.t1059.001]
""", encoding="utf-8")
    (tmp_path / "b.yml").write_text("""
title: two
logsource: {product: windows}
detection:
    selection: {Image: 'y.exe'}
    condition: selection
tags: [attack.impact, attack.t1490]
""", encoding="utf-8")

    assert sigma_loader.load_dir(tmp_path).techniques == {"T1059.001", "T1490"}


def test_a_rule_that_failed_to_load_contributes_no_coverage(tmp_path):
    """The dangerous direction: claiming a technique is covered by a rule that
    is not running."""
    from core import sigma_loader

    (tmp_path / "broken.yml").write_text("""
title: broken
logsource: {product: windows}
detection:
    selection: {Field|nosuchmodifier: 'x'}
    condition: selection
tags: [attack.t1003]
""", encoding="utf-8")

    result = sigma_loader.load_dir(tmp_path)
    assert result.techniques == set()
    assert result.rejected


def test_no_rules_means_no_coverage_claimed(tmp_path):
    from core import sigma_loader
    assert sigma_loader.load_dir(tmp_path).techniques == set()


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

@pytest.mark.parametrize("schema,column", [
    ("db/init.sql", "techniques     VARCHAR(255)"),
    ("Sentora/db/init.sql", "techniques TEXT"),
    ("Sentora/db/init_sqlite.sql", "techniques TEXT"),
])
def test_the_column_exists_in_every_schema(schema, column):
    text = (ROOT / schema).read_text(encoding="utf-8")
    assert column in text, schema


def test_existing_deployments_get_the_column():
    """CREATE TABLE IF NOT EXISTS leaves an existing table alone, so without a
    migration the column only appears on installations made after today."""
    server = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    assert "ALTER TABLE siem_events ADD COLUMN techniques" in server

    agent = (ROOT / "Sentora" / "db" / "init.sql").read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS techniques" in agent


def test_it_is_a_column_not_only_a_json_field():
    """Coverage is a question asked across every event; parsing a text column
    to answer it does not scale and cannot be indexed."""
    server = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    assert "idx_siem_tech" in server


def test_the_agent_writes_it():
    extractor = (ROOT / "Sentora" / "modules" / "log_extractor"
                 / "log_extractor.py").read_text(encoding="utf-8")
    assert "'techniques': ','.join(event.techniques or [])" in extractor


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

FRONTEND = ROOT / "frontend" / "src"


def test_the_page_exists_and_is_routed():
    app_tsx = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    assert "AttackCoverage" in app_tsx
    assert "/attack-coverage" in app_tsx


def test_it_is_reachable_from_the_navigation():
    """A page nobody can find is a page nobody uses."""
    sidebar = (FRONTEND / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    assert "/attack-coverage" in sidebar


def test_the_page_distinguishes_quiet_from_blind():
    """The whole reason this page exists. 'Covered but never seen' is normal;
    'seen with no rule behind it' is not; and a single coverage percentage
    reads as reassurance while hiding which techniques it is silent about."""
    page = (FRONTEND / "pages" / "AttackCoverage.tsx").read_text(encoding="utf-8")
    assert "Covered, never seen" in page
    assert "Seen, no rule behind it" in page


def test_an_empty_grid_says_why_it_is_empty():
    """With no rules installed the grid is empty, and an operator reading it
    as 'nothing to worry about' would be reading it exactly backwards."""
    page = (FRONTEND / "pages" / "AttackCoverage.tsx").read_text(encoding="utf-8")
    assert "No detection rules loaded" in page


def test_a_failed_fetch_is_not_shown_as_zero_coverage():
    """Showing nothing and covering nothing are different claims."""
    page = (FRONTEND / "pages" / "AttackCoverage.tsx").read_text(encoding="utf-8")
    assert "not\n          the same as nothing being covered" in page \
        or "not the same as nothing being covered" in page.replace("\n", " ").replace("  ", " ")


def test_tactics_are_ordered_by_kill_chain_not_alphabetically():
    """A grid sorted alphabetically cannot answer 'where in an intrusion am I
    blind'."""
    page = (FRONTEND / "pages" / "AttackCoverage.tsx").read_text(encoding="utf-8")
    i_initial = page.index("'initial-access'")
    i_impact = page.index("'impact'")
    assert i_initial < i_impact


def test_every_shipped_technique_has_a_tactic_on_the_page():
    """The grid groups by tactic, and an unmapped technique falls into
    "other" - present, but detached from where in a kill chain it sits, which
    is the entire question the grid exists to answer.

    Fails when a rule is added carrying a technique nobody mapped, which is
    when it is cheap to fix rather than months later.
    """
    import re

    from core.sigma_loader import load_dir

    page = (FRONTEND / "pages" / "AttackCoverage.tsx").read_text(encoding="utf-8")
    mapped = set(re.findall(r"\b(T\d{4}):", page))
    shipped = {t.split(".")[0]
               for t in load_dir(ROOT / "Sentora" / "conf" / "sigma").techniques}
    assert not (shipped - mapped), \
        f"shipped techniques with no tactic: {sorted(shipped - mapped)}"


def test_coverage_is_not_zero_out_of_the_box():
    """The page's "No Sigma rules installed" banner is correct advice and was
    also, until rules shipped, what every install saw."""
    from core.sigma_loader import load_dir
    assert load_dir(ROOT / "Sentora" / "conf" / "sigma").techniques


def test_correlation_coverage_is_counted_too():
    """Correlation detects techniques no Sigma rule can express. Leaving it
    out of the index would report T1110.003 as a blind spot on an estate that
    detects it - and the page's whole purpose is telling "quiet" from
    "blind"."""
    body = ast.unparse(_handler("_sigma_technique_index"))
    assert "techniques_covered" in body
    assert "correlation" in body


def test_the_index_survives_one_source_failing():
    """If the Sigma directory is unreadable, correlation coverage is still
    real and should still be reported. Two try blocks, not one - a shared
    handler would silently drop both."""
    body = ast.unparse(_handler("_sigma_technique_index"))
    assert body.count("try:") >= 2


# --------------------------------------------------------------------------
# The documentation quotes numbers. Numbers go stale.
# --------------------------------------------------------------------------

def test_the_documented_rule_and_technique_counts_are_current():
    """README and conf/sigma/README quote "15 rules covering 16 techniques"
    and "19" total. A reader has no way to tell a stale number from a true
    one, and a coverage claim is the worst kind to be wrong about.
    """
    import re

    from core.correlation import techniques_covered
    from core.sigma_loader import load_dir

    loaded = load_dir(ROOT / "Sentora" / "conf" / "sigma")
    sigma_rules = len(loaded.rules)
    sigma_techniques = len(loaded.techniques)
    total = len(loaded.techniques | techniques_covered())

    for name in ("README.md", "Sentora/conf/sigma/README.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for found in re.finditer(r"(\d+) rules? covering (\d+)", text):
            assert int(found.group(1)) == sigma_rules, name
            assert int(found.group(2)) == sigma_techniques, name

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"coverage to {total}" in readme, \
        f"README's total coverage claim is stale; it is now {total}"


def test_correlation_adds_coverage_sigma_cannot_reach():
    """If it added nothing, it would be cost without capability."""
    from core.correlation import techniques_covered
    from core.sigma_loader import load_dir

    sigma = load_dir(ROOT / "Sentora" / "conf" / "sigma").techniques
    assert techniques_covered() - sigma, \
        "correlation covers nothing Sigma does not already"
