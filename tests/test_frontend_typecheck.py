"""`tsc --noEmit -p tsconfig.json` checks nothing in this project.

It exits 0 and prints nothing, for any code, however broken — which is the
worst possible behaviour for a verification command, because silence is what
you are looking for.

The reason is the layout. `frontend/tsconfig.json` is a *solution* file:

    { "files": [], "references": [{"path": "./tsconfig.app.json"},
                                  {"path": "./tsconfig.node.json"}] }

`"files": []` means it owns no sources. Pointing `tsc -p` at it type-checks the
empty set and succeeds. The real settings — `noUnusedLocals` among them — live
in the referenced projects, and only `tsc -b` (build mode) follows references.

`vite build` does not close the gap either: rolldown strips types without
checking them, so it compiles code `tsc` would reject.

This was not theoretical. Two unused imports left behind by a refactor passed
`tsc --noEmit -p tsconfig.json` and passed `vite build`, and were then caught
by the Docker image build — which runs `npm run build` — after the container
had silently kept serving an old agent binary for a day, because the failing
build had never produced a new image.

So: the gate is `npm run build`. These tests make that structural rather than
a thing somebody has to remember.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"


def _jsonc(path: pathlib.Path) -> dict:
    """tsconfig files are JSON with comments."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?<!:)//[^\n]*", "", text)
    return json.loads(text)


def test_the_solution_tsconfig_owns_no_sources():
    """The fact that makes `-p tsconfig.json` useless, pinned.

    If this ever stops being true the trap is gone and this file can go with
    it — but while it holds, a command that looks like a type check is not
    one.
    """
    config = _jsonc(FRONTEND / "tsconfig.json")
    assert config.get("files") == [], (
        "tsconfig.json now owns files; `tsc -p tsconfig.json` may be a real "
        "check again"
    )
    assert config.get("references"), "no project references to build"


def test_the_real_settings_live_in_the_referenced_projects():
    """`noUnusedLocals` is the one that caught the refactor leftovers, and it
    is not in the file `-p` is usually pointed at."""
    solution = _jsonc(FRONTEND / "tsconfig.json")
    assert "noUnusedLocals" not in json.dumps(solution)

    app = _jsonc(FRONTEND / "tsconfig.app.json")
    assert app.get("compilerOptions", {}).get("noUnusedLocals") is True


def test_the_build_script_type_checks_before_bundling():
    """`vite build` alone compiles code `tsc` rejects — rolldown strips types
    without checking them. The `tsc -b` in front of it is the gate."""
    package = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    build = package.get("scripts", {}).get("build", "")
    assert "tsc -b" in build, (
        f"build script is {build!r}; without `tsc -b` nothing type-checks the "
        f"app, because the solution tsconfig owns no files"
    )
    assert "vite build" in build


def test_the_image_build_uses_that_script():
    """The Docker build is what finally reported the error, and only because
    it runs the script rather than a hand-written command."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "npm run build" in dockerfile, (
        "the image builds the frontend some other way, so the type check is "
        "no longer on the path to a release"
    )


@pytest.mark.parametrize("doc", ["README.md", "CONTRIBUTING.md"])
def test_no_document_recommends_the_command_that_checks_nothing(doc):
    """Writing it down is how it spreads."""
    path = ROOT / doc
    if not path.exists():
        pytest.skip(f"{doc} is not in this repository")
    text = path.read_text(encoding="utf-8")
    assert "tsc --noEmit -p tsconfig.json" not in text, (
        f"{doc} recommends a command that type-checks the empty set"
    )
