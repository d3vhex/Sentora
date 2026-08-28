"""Tests for agent config validation.

The case that matters most is the one that is *valid YAML*: a broken regex
parses fine and silently disables the rule containing it. Syntax checking
alone would wave it straight through to the sensor.
"""
from __future__ import annotations

import pytest

from core import config_validation as cv


def errors(issues):
    return [i for i in issues if i.severity == "error"]


def messages(issues):
    return " | ".join(i.message for i in issues)


# --------------------------------------------------------------------------
# rules.yaml
# --------------------------------------------------------------------------

GOOD_RULES = """
flags:
  - IGNORECASE
categories:
  SQL INJECTION:
    severity: CRITICAL
    weight: 5
    patterns: |
      # a comment inside the block
      \\bUNION(\\s+ALL)?\\s+SELECT\\b
      \\bDROP\\s+TABLE\\b
"""


def test_valid_rules_pass():
    assert cv.validate("rules", GOOD_RULES) == []


def test_invalid_regex_is_caught_although_the_yaml_is_valid():
    """The whole point: this parses cleanly and would disable the category."""
    broken = GOOD_RULES.replace(r"\bDROP\s+TABLE\b", "(unclosed group")
    issues = errors(cv.validate("rules", broken))

    assert issues, "an uncompilable regex was accepted"
    assert "invalid regex" in messages(issues)
    assert "SQL INJECTION" in messages(issues)


def test_invalid_regex_reports_the_line_it_is_on():
    broken = GOOD_RULES.replace(r"\bDROP\s+TABLE\b", "*bad-quantifier")
    issue = errors(cv.validate("rules", broken))[0]

    # Counted against the document exactly as submitted — no strip(). The line
    # number has to match what the operator sees in the editor, and GOOD_RULES
    # opens with a newline, so stripping here would report one line too few.
    lines = broken.splitlines()
    expected = next(i for i, l in enumerate(lines, start=1) if "*bad-quantifier" in l)
    assert issue.line == expected, f"reported line {issue.line}, pattern is on {expected}"


def test_line_numbers_are_pinned_to_a_hand_counted_document():
    """Guards the off-by-one directly.

    The line number is the entire point of the feature — an editor that
    highlights the wrong row is worse than one that highlights nothing, so
    the offsets are asserted against a document counted by hand rather than
    against a computed expectation that could drift the same way the code
    does.
    """
    doc = (
        "categories:\n"              # 1
        "  A:\n"                     # 2
        "    severity: HIGH\n"       # 3
        "    weight: 1\n"            # 4
        "    patterns: |\n"          # 5
        "      # comment\n"          # 6
        "      good-one\n"           # 7
        "      (unclosed\n"          # 8
        "      also-good\n"          # 9
        "      +bad\n"               # 10
    )
    found = sorted(i.line for i in errors(cv.validate("rules", doc)))
    assert found == [8, 10], f"expected errors on lines 8 and 10, got {found}"


def test_yaml_syntax_error_reports_a_line():
    issues = errors(cv.validate("rules", "categories:\n  bad: [unclosed\n"))
    assert issues
    assert "YAML syntax error" in issues[0].message
    assert issues[0].line is not None


def test_missing_categories_is_blocked():
    issues = errors(cv.validate("rules", "flags:\n  - IGNORECASE\n"))
    assert issues
    assert "categories" in messages(issues)


def test_category_without_patterns_can_never_match():
    doc = "categories:\n  EMPTY:\n    severity: HIGH\n    weight: 1\n    patterns: ''\n"
    assert "can never match" in messages(errors(cv.validate("rules", doc)))


def test_bad_severity_is_rejected():
    doc = GOOD_RULES.replace("severity: CRITICAL", "severity: SUPER_BAD")
    assert "SUPER_BAD" in messages(errors(cv.validate("rules", doc)))


def test_unknown_flag_warns_but_does_not_block():
    doc = GOOD_RULES.replace("- IGNORECASE", "- NOT_A_FLAG")
    issues = cv.validate("rules", doc)

    assert not errors(issues), "an unknown flag should not block a save"
    assert any(i.severity == "warning" for i in issues)


def test_comments_inside_a_pattern_block_are_not_compiled():
    """`# a comment` is literal content of the block scalar, not YAML."""
    assert cv.validate("rules", GOOD_RULES) == []


# --------------------------------------------------------------------------
# log_paths.yaml
# --------------------------------------------------------------------------

def test_valid_log_paths_pass():
    doc = "log_paths:\n  debian:\n    - /var/log/syslog\n  windows:\n    - 'C:\\\\Windows\\\\Logs\\\\x.log'\n"
    assert errors(cv.validate("log_paths", doc)) == []


def test_missing_root_key_is_blocked():
    """Valid YAML, structurally useless."""
    assert errors(cv.validate("log_paths", "debian:\n  - /var/log/syslog\n"))


def test_relative_path_warns():
    doc = "log_paths:\n  debian:\n    - var/log/syslog\n"
    issues = cv.validate("log_paths", doc)

    assert not errors(issues)
    assert "absolute" in messages(issues)


# --------------------------------------------------------------------------
# file_scan.yaml
# --------------------------------------------------------------------------

def test_valid_file_scan_passes():
    doc = (
        "target_dirs:\n  linux:\n    - /etc\nexclude_dirs:\n  linux:\n    - /proc\n"
        "backup_extensions:\n  - sql.gz\nconfig_regexes:\n  - '.*\\.conf$'\n"
    )
    assert errors(cv.validate("file_scan", doc)) == []


def test_empty_target_dirs_is_blocked():
    assert "nothing to walk" in messages(errors(cv.validate("file_scan", "target_dirs: {}\n")))


def test_invalid_config_regex_is_caught():
    doc = "target_dirs:\n  linux:\n    - /etc\nconfig_regexes:\n  - '(unclosed'\n"
    assert "invalid regex" in messages(errors(cv.validate("file_scan", doc)))


# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------

def test_empty_config_is_blocked():
    """Pushing an empty file would disable detection without erroring."""
    for cfg in cv.CONFIG_TYPES:
        assert "disable" in messages(errors(cv.validate(cfg, "   ")))


def test_unknown_config_type_is_rejected():
    assert errors(cv.validate("passwd", "anything: 1"))


def test_oversized_config_is_rejected():
    huge = "target_dirs:\n  linux:\n" + ("    - /x\n" * 200_000)
    assert "limit" in messages(errors(cv.validate("file_scan", huge)))


@pytest.mark.parametrize("cfg", cv.CONFIG_TYPES)
def test_validate_never_raises(cfg):
    """The endpoint calls this on operator input; an exception here would be
    a 500 on every malformed paste."""
    for junk in ("\x00\x01", "!!python/object:os.system 'x'", "[", "a: [1,", "%YAML 1.9\n---\n"):
        cv.validate(cfg, junk)


# --------------------------------------------------------------------------
# A rejected severity should name the likely intent
# --------------------------------------------------------------------------
#
# An agent in the field carried `severity: INFORMATIVE`, and the message read
# "is not one of CRITICAL, HIGH, INFO, LOW, MEDIUM" - correct, and it left the
# operator to work out which of the five was meant.
#
# Worth blocking on rather than warning about: `core.triage` deliberately
# *keeps* events whose severity it cannot read, so that a missing field never
# silently means "below the floor". A typo therefore does not disable the
# category - it exempts it from the floor and sends every one of its events to
# the model.

def test_the_case_that_actually_happened():
    doc = GOOD_RULES.replace("severity: CRITICAL", "severity: INFORMATIVE")
    issues = cv.validate("rules", doc)
    message = " ".join(i.message for i in issues)
    assert "INFORMATIVE" in message
    assert "Did you mean `INFO`?" in message


def test_a_suggestion_is_offered_only_when_there_is_one():
    """Pointing an operator at a word they never wrote is worse than not
    guessing."""
    doc = GOOD_RULES.replace("severity: CRITICAL", "severity: BANANA")
    issues = cv.validate("rules", doc)
    message = " ".join(i.message for i in issues)
    assert "BANANA" in message
    assert "Did you mean" not in message


def test_valid_severities_still_pass_untouched():
    """The suggestion must not fire on anything correct."""
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        doc = GOOD_RULES.replace("severity: CRITICAL", f"severity: {severity}")
        assert not errors(cv.validate("rules", doc)), severity


def test_the_shipped_rules_file_validates():
    """The repository's own rules.yaml is what a fresh agent gets, and it is
    the file this error was reported against. If it does not pass its own
    validator, every install starts with a config the console refuses."""
    import pathlib
    shipped = (pathlib.Path(__file__).resolve().parent.parent
               / "Sentora" / "conf" / "rules.yaml").read_text(encoding="utf-8")
    found = errors(cv.validate("rules", shipped))
    assert not found, [i.message for i in found]
