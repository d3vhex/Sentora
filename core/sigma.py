"""Sigma rules, compiled to a predicate that runs against an event dict.

Sigma is the format detection engineers already write in, so supporting it
means the thousands of community rules become available and nobody has to
trust a rule list that only exists in this repository. `conf/rules.yaml` is
1575 regexes nobody outside this project has reviewed; a Sigma rule has a
provenance, an author and a history.

Why not pysigma
---------------
pysigma compiles Sigma to *query languages* - Splunk SPL, Elasticsearch DSL,
a dozen others. There is no backend that answers "does this dict match", which
is the only question the agent needs, and it brings a large dependency tree to
a component that runs on every endpoint. This evaluates in process instead.

What it refuses
---------------
An unsupported construct raises rather than compiling to something that
happens to be false. A detection rule that silently never fires is worse than
one that fails to load: the second is visible on the next start, the first is
discovered after an intrusion. `UnsupportedRule` names the construct and the
rule it came from.
"""

from __future__ import annotations

import base64
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Callable

try:
    import yaml
except ImportError:                                   # pragma: no cover
    yaml = None


class SigmaError(Exception):
    """The rule is not usable."""


class UnsupportedRule(SigmaError):
    """A construct this evaluator does not implement.

    Raised rather than skipped. See the module docstring.
    """


# Modifiers, in the order Sigma applies them. `all` is handled separately
# because it changes how a list is combined rather than how a value matches.
_VALUE_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "base64", "base64offset",
    "windash", "cidr", "utf16le", "utf16be", "utf16", "wide",
}

# Sigma's text-encoding modifiers, applied before base64 rather than after.
#
# These are not decoration. PowerShell's -EncodedCommand takes UTF-16LE, so a
# needle encoded as UTF-8 and then base64'd cannot appear in the payload at
# all - it would match nothing, quietly, forever. `wide` is Sigma's older
# spelling of utf16le and means the same thing.
_ENCODINGS = {
    "utf16le": "utf-16-le",
    "wide": "utf-16-le",
    "utf16be": "utf-16-be",
    "utf16": "utf-16",          # with the byte-order mark
}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _windash_variants(needle: str) -> list[str]:
    """`-flag`, `/flag`, `–flag`. Attackers use whichever the shell accepts."""
    out = {needle}
    for dash in ("-", "/", "–", "—"):
        if needle[:1] in ("-", "/", "–", "—"):
            out.add(dash + needle[1:])
    return sorted(out)


def _build_value_test(raw: Any, modifiers: list[str]) -> Callable[[str], bool]:
    """One field/value pair, as a test against the field's text."""
    unknown = [m for m in modifiers if m not in _VALUE_MODIFIERS and m != "all"]
    if unknown:
        raise UnsupportedRule(f"modifier(s) {unknown} are not implemented")

    if "cidr" in modifiers:
        import ipaddress
        network = ipaddress.ip_network(str(raw), strict=False)

        def in_cidr(text: str) -> bool:
            try:
                return ipaddress.ip_address(text.strip()) in network
            except ValueError:
                return False
        return in_cidr

    if "re" in modifiers:
        pattern = re.compile(str(raw), re.IGNORECASE | re.DOTALL)
        return lambda text: bool(pattern.search(text))

    needles = [_as_text(raw)]

    codec = next((_ENCODINGS[m] for m in modifiers if m in _ENCODINGS), None)
    if codec and not ({"base64", "base64offset"} & set(modifiers)):
        # Alone, an encoding modifier would compare UTF-16 bytes against text
        # that is already str, and never be equal. Sigma defines it only as a
        # step before base64, so anything else is a bug in the rule and is
        # named rather than compiled into something that silently never fires.
        raise UnsupportedRule(
            "encoding modifier must be followed by base64 or base64offset")

    def _encode(text: str) -> bytes:
        return text.encode(codec) if codec else text.encode()

    if "base64" in modifiers:
        needles = [base64.b64encode(_encode(n)).decode() for n in needles]
    elif "base64offset" in modifiers:
        # The same string encoded at each of the three byte alignments, which
        # is how it appears once embedded in a larger blob.
        #
        # Both ends have to be trimmed, not just the leading one. base64 packs
        # three bytes into four characters, so the first and last groups are
        # shared with whatever surrounds the needle - a needle carrying its own
        # final group matches only when it happens to sit at the very end of
        # the payload. That is why an earlier version found "Net.WebClient" in
        # nothing at all.
        #
        # How much to trim from the end depends on where the needle *ends*,
        # which is the padding plus its own length - not on the padding alone.
        starts, ends = (0, 2, 3), (None, -3, -2)
        expanded = []
        for n in needles:
            encoded_bytes = _encode(n)
            for pad in range(3):
                blob = base64.b64encode(b" " * pad + encoded_bytes).decode()
                expanded.append(
                    blob[starts[pad]:ends[(len(encoded_bytes) + pad) % 3]])
        needles = expanded
    if "windash" in modifiers:
        needles = [v for n in needles for v in _windash_variants(n)]

    lowered = [n.lower() for n in needles]

    if "contains" in modifiers:
        return lambda text: any(n in text.lower() for n in lowered)
    if "startswith" in modifiers:
        return lambda text: any(text.lower().startswith(n) for n in lowered)
    if "endswith" in modifiers:
        return lambda text: any(text.lower().endswith(n) for n in lowered)

    # Bare value. Sigma treats `*` as a wildcard even without a modifier.
    def equals_or_glob(text: str) -> bool:
        low = text.lower()
        return any(fnmatch.fnmatchcase(low, n) if ("*" in n or "?" in n)
                   else low == n
                   for n in lowered)
    return equals_or_glob


def _as_list(value) -> list[str]:
    """Sigma allows a single string where a list is expected."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    return [str(v).strip() for v in value if str(v).strip()]


@dataclass
class SigmaRule:
    """A parsed rule and the predicate its detection compiles to."""

    id: str
    title: str
    level: str
    logsource: dict
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""
    # What benign thing looks like this. The rule author is the only person
    # who reliably knows, and the analyst deciding whether to dismiss the
    # alert at 3am is the person who needs it - so it is carried through to
    # the event rather than left in the YAML.
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source_path: str = ""
    _predicate: Callable[[dict], bool] | None = None

    def matches(self, event: dict) -> bool:
        return bool(self._predicate and self._predicate(event))


_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def _split_tags(tags: list) -> tuple[list[str], list[str]]:
    """(techniques, tactics) out of Sigma's flat `tags` list.

    Sigma writes `attack.t1059.001` for a technique and `attack.execution` for
    a tactic, in the same list. This is where MITRE coverage comes from - the
    rules already carry it, so nothing has to be mapped by hand.
    """
    techniques, tactics = [], []
    for tag in tags or []:
        text = str(tag).strip()
        m = _ATTACK_TECHNIQUE.match(text)
        if m:
            techniques.append(m.group(1).upper())
        elif text.lower().startswith("attack."):
            tactics.append(text.split(".", 1)[1].replace("_", "-").lower())
    return techniques, tactics


def _field_values(event: dict, name: str) -> list[str]:
    """Every value the event offers for a Sigma field name.

    Matched case-insensitively: Sigma rules write `CommandLine`, different
    producers write `commandline` or `command_line`, and a rule that silently
    matches nothing because of capitalisation is the failure this whole module
    exists to avoid.
    """
    wanted = name.lower().replace("_", "")
    out = []
    for key, value in event.items():
        if str(key).lower().replace("_", "") == wanted:
            if isinstance(value, (list, tuple)):
                out.extend(_as_text(v) for v in value)
            else:
                out.append(_as_text(value))
    return out


def _compile_field(name: str, raw: Any) -> Callable[[dict], bool]:
    parts = name.split("|")
    field_name, modifiers = parts[0], [p.lower() for p in parts[1:]]

    values = raw if isinstance(raw, list) else [raw]
    tests = [_build_value_test(v, modifiers) for v in values]
    require_all = "all" in modifiers

    def test(event: dict) -> bool:
        present = _field_values(event, field_name)
        if not present:
            # A rule asking about a field the event does not have is not a
            # match. Treating absence as a match would fire every rule on
            # every event from a producer that names its fields differently.
            return False
        if require_all:
            return all(any(t(v) for v in present) for t in tests)
        return any(t(v) for v in present for t in tests)

    return test


def _compile_selection(spec: Any) -> Callable[[dict], bool]:
    """A named selection: a map (AND over fields) or a list of maps (OR)."""
    if isinstance(spec, list):
        subs = [_compile_selection(s) for s in spec]
        return lambda event: any(s(event) for s in subs)
    if isinstance(spec, dict):
        tests = [_compile_field(k, v) for k, v in spec.items()]
        return lambda event: all(t(event) for t in tests)
    raise UnsupportedRule(f"selection must be a map or list, got {type(spec).__name__}")


_CONDITION_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|[\w*]+)\s*", re.I)


def _compile_condition(condition: str, selections: dict) -> Callable[[dict], bool]:
    """Sigma's condition mini-language.

    Supports `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`,
    `1 of them`, `all of them`. Anything else raises - see the module
    docstring on why an unsupported construct must not compile to False.
    """
    text = " ".join(str(condition).split())
    if not text:
        raise UnsupportedRule("empty condition")

    # `1 of selection*` / `all of them` are rewritten to an explicit or/and
    # over the selections they name, before the expression is parsed.
    def expand(match: re.Match) -> str:
        quantifier, pattern = match.group(1).lower(), match.group(2)
        if pattern == "them":
            names = list(selections)
        else:
            names = [n for n in selections if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise UnsupportedRule(f"'{quantifier} of {pattern}' matches no selection")
        joiner = " or " if quantifier in ("1", "any") else " and "
        return "(" + joiner.join(names) + ")"

    text = re.sub(r"\b(1|any|all)\s+of\s+([\w*]+)", expand, text, flags=re.I)

    tokens = [t for t in _CONDITION_TOKEN.findall(text) if t]
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        left = parse_and()
        while peek() == "or":
            take()
            right = parse_and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def parse_and():
        left = parse_not()
        while peek() == "and":
            take()
            right = parse_not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def parse_not():
        if peek() == "not":
            take()
            inner = parse_not()
            return lambda e: not inner(e)
        return parse_atom()

    def parse_atom():
        tok = take()
        if tok == "(":
            inner = parse_or()
            if peek() != ")":
                raise UnsupportedRule(f"unbalanced parentheses in {condition!r}")
            take()
            return inner
        if tok not in selections:
            raise UnsupportedRule(f"condition names unknown selection {tok!r}")
        return selections[tok]

    predicate = parse_or()
    if pos != len(tokens):
        raise UnsupportedRule(f"could not parse condition {condition!r}")
    return predicate


def parse(text: str, source_path: str = "") -> SigmaRule:
    """Parse one Sigma rule. Raises SigmaError if it is not usable."""
    if yaml is None:
        raise SigmaError("PyYAML is not installed; Sigma rules cannot be loaded")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SigmaError(f"not valid YAML: {e}") from e
    if not isinstance(doc, dict):
        raise SigmaError("a Sigma rule must be a YAML mapping")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError("rule has no detection block")
    condition = detection.get("condition")
    if condition is None:
        raise SigmaError("detection block has no condition")
    if isinstance(condition, list):
        # Sigma allows a list of conditions, meaning OR.
        condition = " or ".join(f"({c})" for c in condition)

    selections = {name: _compile_selection(spec)
                  for name, spec in detection.items() if name != "condition"}
    predicate = _compile_condition(condition, selections)

    techniques, tactics = _split_tags(doc.get("tags") or [])
    return SigmaRule(
        id=str(doc.get("id") or "").strip(),
        title=str(doc.get("title") or "").strip() or "(untitled)",
        level=str(doc.get("level") or "medium").strip().lower(),
        logsource=doc.get("logsource") or {},
        techniques=techniques,
        tactics=tactics,
        tags=[str(t) for t in (doc.get("tags") or [])],
        description=str(doc.get("description") or "").strip(),
        falsepositives=_as_list(doc.get("falsepositives")),
        references=_as_list(doc.get("references")),
        source_path=source_path,
        _predicate=predicate,
    )


# Sigma's levels, mapped to the severities this platform already uses.
LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}


def severity_of(rule: SigmaRule) -> str:
    return LEVEL_TO_SEVERITY.get(rule.level, "MEDIUM")
