"""`sudo bash ./build_agent.sh` has to be the whole instruction.

On a stock Ubuntu image it was not. The script assumed pip, a compiler, and
headers it never installed, and the first thing a fresh EC2 box said was:

    [*] Installing pip dependencies...
    /usr/bin/python3: No module named pip

Three separate assumptions, each of which fails at a different point and none
of which mentions what is missing:

  - `python3-pip` is a separate package on Debian and Ubuntu.
  - Since 24.04, PEP 668 refuses installs into the system interpreter even
    once pip exists.
  - `cysystemd` has no wheel. It compiles against libsystemd, so it needs
    gcc, python3-dev, pkg-config and libsystemd-dev - and fails several
    minutes in, with a compiler error that names none of them.

These tests read the script rather than running it: the failure modes are
apt-shaped and Debian-shaped, and a test that could reproduce them would have
to be a container. What they pin is that the handling is still there.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "Sentora" / "build_agent.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")


def _assert_bash_accepted(result, what: str) -> None:
    """Fail on a syntax error; skip when bash never ran the script.

    On Windows the `bash` on PATH is usually the WSL shim, and when the WSL
    virtual machine will not start it exits non-zero having never read stdin -
    writing its own complaint to *stdout*, in the system language, with stderr
    empty:

        b'S\\x00a\\x00n\\x00a\\x00l\\x00 \\x00m\\x00a\\x00k\\x00i\\x00n\\x00e...'
        (UTF-16LE: "Sanal makine ... CONNECTION_TIMEOUT")

    Read as a failure that says `assert 1 == 0`, which is a broken build
    script - and it took a real bash error to tell them apart. A syntax error
    always names itself on stderr; an unrunnable shell leaves it empty. The
    distinction matters more than the convenience: a test that reports the
    environment as the code is a test that gets ignored.
    """
    if result.returncode == 0:
        return
    stderr = result.stderr.decode("utf-8", "replace").strip()
    if not stderr:
        noise = result.stdout.decode("utf-16-le", "replace").strip() \
            or result.stdout.decode("utf-8", "replace").strip()
        pytest.skip(f"bash did not run: {noise[:200] or 'no output'}")
    raise AssertionError(f"{what} is not valid bash:\n{stderr}")


def test_the_script_is_valid_bash():
    """`set -euo pipefail` plus a syntax error is a script that fails on line
    one with no output at all.

    Fed on stdin rather than by path: whichever bash is on PATH here may not
    share this machine's filesystem view - a Windows path is rejected, and the
    Git-Bash spelling of it is rejected by WSL. The content is the same either
    way and needs no path at all.
    """
    if shutil.which("bash") is None:
        pytest.skip("no bash on PATH")
    # utf-8 explicitly: the script's section rules are box-drawing characters,
    # and Python defaults to the console codepage on Windows, which cannot
    # encode them - the test then fails on the pipe rather than on the script.
    # Bytes, not text. With text=True Python writes os.linesep, so on Windows
    # every newline reaches bash as CRLF and it reports a syntax error at the
    # first function definition - a failure that looks like the script and is
    # the pipe.
    result = subprocess.run(["bash", "-n"], input=SCRIPT.read_bytes(),
                            capture_output=True)
    _assert_bash_accepted(result, SCRIPT.name)


@pytest.mark.parametrize("package", [
    "python3-venv",      # PEP 668 makes this the only sane path
    "python3-dev",       # cysystemd compiles against Python headers
    "gcc",
    "pkg-config",
    "libsystemd-dev",    # the one nothing else would tell you about
    "binutils",          # PyInstaller shells out to objdump
])
def test_every_apt_package_the_build_needs_is_installed(package):
    assert package in TEXT, f"{package} is needed and never installed"


def test_missing_packages_are_detected_before_they_are_needed():
    """Discovering libsystemd-dev is missing *during* a pip build means
    waiting several minutes for a compiler error that does not name it."""
    assert "dpkg -s" in TEXT
    assert "apt-get install" in TEXT


def test_it_says_to_use_sudo_rather_than_failing_on_permissions():
    """Without root, apt fails with its own error and the reader is left to
    work out that the script needed privileges."""
    assert 'id -u' in TEXT
    assert "sudo bash" in TEXT


def test_the_build_runs_in_a_virtualenv():
    """Installing into the system interpreter is refused outright on Ubuntu
    24.04 and newer, and is rude on the versions that still allow it - this
    is somebody's server."""
    assert "python3 -m venv" in TEXT
    assert 'PY="$VENV/bin/python"' in TEXT


def test_pyinstaller_runs_from_that_virtualenv():
    """The dependencies go in the venv. Invoking the system interpreter would
    then fail on the first import, having installed everything correctly."""
    assert '"$PY" -m PyInstaller' in TEXT
    assert "python3 -m PyInstaller" not in TEXT


def test_the_clean_step_keeps_the_virtualenv():
    """Rebuilding cysystemd from source on every run turns a two-minute
    rebuild into a ten-minute one."""
    # The command, not the comment above it - which mentions .venv-build
    # precisely because it is explaining why the venv is spared.
    removals = [line for line in TEXT.splitlines()
                if line.strip().startswith("rm -rf") and "$SCRIPT_DIR/build" in line]
    assert removals, "the clean step disappeared"
    for line in removals:
        assert ".venv-build" not in line, line


def test_skip_deps_still_prefers_the_venv():
    """Otherwise `--skip-deps` silently falls back to a system interpreter
    that has none of this installed, and fails on the first import."""
    else_branch = TEXT[TEXT.index('warn "Skipping dependency install') - 400:]
    else_branch = else_branch[:else_branch.index("Skipping dependency install")]
    assert 'PY="$VENV/bin/python"' in else_branch


def test_a_missing_pyinstaller_is_caught_before_the_long_part():
    """`--skip-deps` on a machine that never ran the full build otherwise
    reaches the PyInstaller invocation and fails there."""
    assert 'import PyInstaller' in TEXT


def test_the_artifact_is_given_back_to_the_invoking_user():
    """Built as root under sudo, the binary is root-owned - and the next run
    fails with a permission error from PyInstaller that says nothing about
    ownership."""
    assert "SUDO_USER" in TEXT
    assert "chown" in TEXT


def test_the_venv_is_not_committed():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".venv-build" in ignore


def test_the_usage_text_still_matches_the_flags():
    """`usage()` is `sed -n '2,15p'` over this file - a fixed line range, so
    inserting anything above it silently prints the wrong thing.

    Reproduced here rather than run, for the same reason as the syntax check:
    `usage()` reads `$0`, so feeding the script on stdin would make it print
    bash's own source.
    """
    printed = "\n".join(TEXT.splitlines()[1:15])
    for flag in ("--no-clean", "--skip-deps", "--help"):
        assert flag in printed, f"{flag} is not in the help text"
    assert "Usage:" in printed
    assert "build_agent.sh" in printed


def test_the_documented_flags_are_the_implemented_flags():
    implemented = set(re.findall(r"^\s+(--[a-z-]+)\)", TEXT, re.M))
    assert {"--no-clean", "--skip-deps"} <= implemented


@pytest.mark.parametrize("script", sorted(
    str(p.relative_to(ROOT)) for p in ROOT.rglob("*.sh")
    if not any(part in {".git", "node_modules", "backups", ".venv-build"}
               for part in p.parts)))
def test_shell_scripts_use_unix_line_endings(script):
    """A `.sh` with CRLF does not run on Linux at all. bash reports a syntax
    error at the first `{`, naming a line that is perfectly valid, and the
    reader goes looking at the wrong thing.

    This repository is edited on Windows, where more than one tool rewrites
    line endings on save without being asked. `build_agent.sh` is the file
    that has to survive being copied to a fresh Ubuntu box and run once.
    """
    raw = (ROOT / script).read_bytes()
    assert bytes([13, 10]) not in raw, f"{script} has CRLF line endings"


def test_gitattributes_pins_shell_scripts_to_lf():
    """The test above catches a CRLF script already in the tree. This is what
    stops one getting there: without it, a Windows checkout with
    core.autocrlf=true rewrites `.sh` on the way out and the file that reaches
    the Ubuntu box is unrunnable, whatever the repository holds."""
    attributes = ROOT / ".gitattributes"
    assert attributes.exists(), "no .gitattributes"
    text = attributes.read_text(encoding="utf-8")
    assert "*.sh" in text
    assert "eol=lf" in text


def test_powershell_scripts_are_not_forced_to_lf():
    """They only run on Windows, and some older hosts are unhappy with
    LF-only. Forcing every script one way would trade this bug for its
    mirror image."""
    text = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    ps1 = next(l for l in text.splitlines() if l.startswith("*.ps1"))
    assert "crlf" in ps1


# --------------------------------------------------------------------------
# The two builds must ship the same agent
# --------------------------------------------------------------------------
#
# Windows and Linux have separate build scripts with separately maintained
# hidden-import lists. PyInstaller does not walk the imports of a module that
# is itself a hidden import, so anything reached only from one of those has to
# be listed too - and it has to be listed in *both*.
#
# The failure is quiet in the worst way: the binary builds cleanly, ships, and
# dies at the moment the missing import is first executed. `modules.version`
# is reached only from `modules.link`, so leaving it out of one script would
# produce an agent that installs fine and dies on its first channel connect,
# on one platform only.

PS1 = ROOT / "Sentora" / "build_agent.ps1"


def _hidden_imports(text: str) -> set[str]:
    import re

    found = set(re.findall(r"--hidden-import\s+([\w.]+)", text))
    # The PowerShell script keeps them in an array of quoted strings.
    block = re.search(r"\$hiddenImports\s*=\s*@\((.*?)\)", text, re.S)
    if block:
        found |= set(re.findall(r'"([\w.]+)"', block.group(1)))
    return found


def test_both_builds_declare_the_same_agent_modules():
    linux = _hidden_imports(SCRIPT.read_text(encoding="utf-8"))
    windows = _hidden_imports(PS1.read_text(encoding="utf-8"))
    assert linux, "no hidden imports found in build_agent.sh; the scan is broken"

    # Windows-only packages are expected to be one-sided.
    windows_only = {"winpty", "winpty.ptyprocess"}
    linux_only = {"mss.linux"}

    missing_from_windows = {m for m in linux if m.startswith("modules.")} - windows
    missing_from_linux = {m for m in windows if m.startswith("modules.")} - linux
    assert not missing_from_windows,         f"build_agent.ps1 does not bundle {sorted(missing_from_windows)}"
    assert not missing_from_linux,         f"build_agent.sh does not bundle {sorted(missing_from_linux)}"
    assert windows_only <= windows
    assert linux_only <= linux


def test_the_version_module_is_bundled():
    """Reached only from `modules.link`, which is itself a hidden import, so
    PyInstaller never finds it on its own."""
    for script in (SCRIPT, PS1):
        assert "modules.version" in _hidden_imports(script.read_text(encoding="utf-8")),             f"{script.name} would build an agent that cannot report its version"
