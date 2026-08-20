"""Validation for the agent YAML configs before they are pushed to a sensor.

`POST /<agent>/config/<cfg_type>` used to forward the request body to the
agent unread. A typo therefore reached the sensor, and the failure surfaced
as the agent quietly not detecting things any more — the worst possible
failure mode for a security tool, because nothing looks wrong.

Three layers, cheapest first:

1. **Parse.** YAML syntax, with the line and column YAML itself reports.
2. **Shape.** Each config type has a known top-level structure; a `log_paths`
   file that lost its root key is valid YAML and useless.
3. **Regexes.** The patterns in rules.yaml and file_scan.yaml are compiled.
   This is the layer that matters most: an invalid regex is perfectly valid
   YAML and disables the rule that contains it. `re` is what the agent uses,
   so compiling here answers the same question the agent will ask.

Everything is reported as a list of `Issue` with a line number, so the editor
can point at the problem instead of saying "invalid".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any

import yaml

CONFIG_TYPES = ("rules", "log_paths", "file_scan")

# A sensor config is a few hundred KB at most. The cap is here so a paste
# accident cannot push megabytes of anything at every enrolled endpoint.
MAX_BYTES = 512 * 1024

VALID_REGEX_FLAGS = {
    "IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE", "UNICODE", "ASCII", "LOCALE",
}

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@dataclass
class Issue:
    line: int | None          # 1-based; None when the problem has no location
    message: str
    severity: str = "error"   # "error" blocks the save, "warning" does not

    def to_dict(self) -> dict:
        return asdict(self)


def _err(msg: str, line: int | None = None) -> Issue:
    return Issue(line=line, message=msg, severity="error")


def _warn(msg: str, line: int | None = None) -> Issue:
    return Issue(line=line, message=msg, severity="warning")


def _compile_patterns(block: str, first_line: int, label: str) -> list[Issue]:
    """Compile each non-comment line of a pattern block.

    The block scalars in rules.yaml carry their own `#` comments as literal
    content, so those are skipped the same way the agent skips them.
    `first_line` is the document line the block's first line sits on, which
    lets an offending pattern be pointed at directly.
    """
    issues: list[Issue] = []
    for offset, raw in enumerate(block.splitlines()):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        try:
            re.compile(raw.strip())
        except re.error as e:
            issues.append(_err(
                f"{label}: invalid regex ({e.msg}) in `{text[:60]}`",
                line=first_line + offset,
            ))
    return issues


def _scalar_line(node: yaml.Node) -> int:
    """1-based document line for a node."""
    return node.start_mark.line + 1


def _find_block_lines(root: yaml.Node) -> dict[int, int]:
    """Map id(node) -> first content line, for every scalar in the tree.

    Block scalars (`patterns: |`) start their content on the line after the
    indicator, which is what makes per-pattern line numbers possible.
    """
    lines: dict[int, int] = {}

    def walk(node: yaml.Node) -> None:
        if isinstance(node, yaml.ScalarNode):
            start = node.start_mark.line + 1
            # A block scalar's mark sits on the `|`; content begins next line.
            if node.style in ("|", ">"):
                start += 1
            lines[id(node)] = start
        elif isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                walk(k)
                walk(v)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                walk(item)

    walk(root)
    return lines


def _pattern_nodes(root: yaml.Node) -> list[tuple[str, yaml.ScalarNode]]:
    """Locate every `patterns` value under `categories`, with its category name."""
    found: list[tuple[str, yaml.ScalarNode]] = []
    if not isinstance(root, yaml.MappingNode):
        return found

    for key, value in root.value:
        if not (isinstance(key, yaml.ScalarNode) and key.value == "categories"):
            continue
        if not isinstance(value, yaml.MappingNode):
            continue
        for cat_key, cat_val in value.value:
            name = cat_key.value if isinstance(cat_key, yaml.ScalarNode) else "?"
            if not isinstance(cat_val, yaml.MappingNode):
                continue
            for k2, v2 in cat_val.value:
                if isinstance(k2, yaml.ScalarNode) and k2.value == "patterns":
                    if isinstance(v2, yaml.ScalarNode):
                        found.append((str(name), v2))
    return found


def _validate_rules(data: Any, root: yaml.Node | None) -> list[Issue]:
    issues: list[Issue] = []
    if not isinstance(data, dict):
        return [_err("rules.yaml must be a mapping with `flags` and `categories`")]

    flags = data.get("flags")
    if flags is not None:
        if not isinstance(flags, list):
            issues.append(_err("`flags` must be a list"))
        else:
            for f in flags:
                if str(f).upper() not in VALID_REGEX_FLAGS:
                    issues.append(_warn(
                        f"Unknown regex flag `{f}` — the agent will ignore it. "
                        f"Known flags: {', '.join(sorted(VALID_REGEX_FLAGS))}"
                    ))

    categories = data.get("categories")
    if not isinstance(categories, dict) or not categories:
        issues.append(_err("`categories` must be a non-empty mapping; without it the agent detects nothing"))
        return issues

    for name, body in categories.items():
        if not isinstance(body, dict):
            issues.append(_err(f"Category `{name}` must be a mapping with severity/weight/patterns"))
            continue

        sev = str(body.get("severity", "")).upper()
        if not sev:
            issues.append(_err(f"Category `{name}` is missing `severity`"))
        elif sev not in SEVERITIES:
            issues.append(_err(
                f"Category `{name}`: severity `{body.get('severity')}` is not one of "
                f"{', '.join(sorted(SEVERITIES))}"
            ))

        weight = body.get("weight")
        if weight is None:
            issues.append(_warn(f"Category `{name}` has no `weight`; scoring will treat it as 0"))
        elif not isinstance(weight, (int, float)):
            issues.append(_err(f"Category `{name}`: `weight` must be a number, got `{weight}`"))

        if not str(body.get("patterns") or "").strip():
            issues.append(_err(f"Category `{name}` has no patterns; it can never match"))

    # Regex compilation, with real line numbers where the tree is available.
    if root is not None:
        block_lines = _find_block_lines(root)
        for cat_name, node in _pattern_nodes(root):
            issues.extend(_compile_patterns(
                node.value, block_lines.get(id(node), 1), f"Category `{cat_name}`"
            ))
    else:
        for name, body in categories.items():
            if isinstance(body, dict):
                issues.extend(_compile_patterns(str(body.get("patterns") or ""), 1, f"Category `{name}`"))

    return issues


def _validate_log_paths(data: Any) -> list[Issue]:
    if not isinstance(data, dict):
        return [_err("log_paths.yaml must be a mapping")]

    paths = data.get("log_paths")
    if not isinstance(paths, dict) or not paths:
        return [_err("`log_paths` must be a non-empty mapping of distro -> list of paths")]

    issues: list[Issue] = []
    for distro, entries in paths.items():
        if not isinstance(entries, list):
            issues.append(_err(f"`log_paths.{distro}` must be a list of paths"))
            continue
        for p in entries:
            if not isinstance(p, str) or not p.strip():
                issues.append(_err(f"`log_paths.{distro}` contains a non-string entry: {p!r}"))
            elif not (p.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", p)):
                issues.append(_warn(
                    f"`{p}` is not an absolute path; the agent resolves these relative to its "
                    f"working directory, which is rarely what you want"
                ))
    return issues


def _validate_file_scan(data: Any) -> list[Issue]:
    if not isinstance(data, dict):
        return [_err("file_scan.yaml must be a mapping")]

    issues: list[Issue] = []
    for key in ("target_dirs", "exclude_dirs"):
        section = data.get(key)
        if section is None:
            issues.append(_warn(f"`{key}` is missing"))
            continue
        if not isinstance(section, dict):
            issues.append(_err(f"`{key}` must be a mapping of os -> list of directories"))
            continue
        for os_name, dirs in section.items():
            if dirs is None:
                continue
            if not isinstance(dirs, list):
                issues.append(_err(f"`{key}.{os_name}` must be a list"))

    if not data.get("target_dirs"):
        issues.append(_err("`target_dirs` is empty; the scanner would have nothing to walk"))

    exts = data.get("backup_extensions")
    if exts is not None and not isinstance(exts, list):
        issues.append(_err("`backup_extensions` must be a list"))

    regexes = data.get("config_regexes")
    if regexes is not None:
        if not isinstance(regexes, list):
            issues.append(_err("`config_regexes` must be a list"))
        else:
            for rx in regexes:
                try:
                    re.compile(str(rx))
                except re.error as e:
                    issues.append(_err(f"config_regexes: invalid regex ({e.msg}) in `{str(rx)[:60]}`"))

    return issues


def validate(cfg_type: str, content: str) -> list[Issue]:
    """Validate a config document. An empty list means it is safe to push."""
    if cfg_type not in CONFIG_TYPES:
        return [_err(f"Unknown config type `{cfg_type}`; expected one of {', '.join(CONFIG_TYPES)}")]

    if content is None or not str(content).strip():
        return [_err("Config is empty. Pushing this would disable the agent's detection.")]

    encoded = str(content).encode("utf-8")
    if len(encoded) > MAX_BYTES:
        return [_err(f"Config is {len(encoded) // 1024} KB; the limit is {MAX_BYTES // 1024} KB")]

    # compose() keeps the node tree, and with it the source marks that make
    # per-pattern line numbers possible. safe_load() throws those away.
    try:
        root = yaml.compose(content)
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        problem = getattr(e, "problem", None) or "invalid YAML"
        context = getattr(e, "context", None)
        detail = f"{context}, {problem}" if context else problem
        return [_err(f"YAML syntax error: {detail}", line=(mark.line + 1) if mark else None)]

    if data is None:
        return [_err("Config parsed as empty")]

    if cfg_type == "rules":
        return _validate_rules(data, root)
    if cfg_type == "log_paths":
        return _validate_log_paths(data)
    return _validate_file_scan(data)


def blocking(issues: list[Issue]) -> list[Issue]:
    return [i for i in issues if i.severity == "error"]
