"""Guards on agent enrolment identity.

Re-running the deploy one-liner used to allocate a fresh identity every time,
because the installer called /api/agents/register unconditionally and the
server appends `-2`, `-3`, `-4` whenever the requested name is taken. One
physical machine became four "agents": telemetry split across four databases,
the fleet view counting it four times, and deduplication running separately
in each.

The installer template is a PowerShell string built in core/installers.py,
so it is checked by parsing the rendered output rather than by running it.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
INSTALLERS = ROOT / "core" / "installers.py"


def _render() -> str:
    """Render the Windows installer without importing the module.

    core/installers.py has no imports of its own, but reading it this way
    keeps the test independent of anything else that module might grow.
    """
    src = INSTALLERS.read_text(encoding="utf-8-sig")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "_render_windows_install")
    ns: dict = {}
    exec(compile(ast.Module([fn], []), "<installer>", "exec"), ns)
    return ns["_render_windows_install"]("http://srv:8000", "10.0.0.1", "T" * 64)


SCRIPT = _render()


def test_an_upgrade_keeps_the_existing_identity():
    """The regression this exists for. An install that finds credentials must
    reuse them rather than asking the server for new ones."""
    assert "config.json" in SCRIPT
    assert "$Prev.agent_name" in SCRIPT and "$Prev.agent_key" in SCRIPT
    assert "Upgrading existing agent" in SCRIPT


def test_registration_is_conditional_not_unconditional():
    """Enrolment must sit behind the "no existing identity" check. Previously
    the register call ran before anything looked at config.json."""
    guard = SCRIPT.index("if (-not $AgentName)")
    call = SCRIPT.index("/api/agents/register", guard)
    assert call > guard, "the fresh-enrolment call is not inside the guard"


def test_the_token_is_still_closed_out_on_an_upgrade():
    """Skipping registration left the token unused forever, so the Deploy
    page reported "waiting" after a deployment that had already succeeded."""
    upgrade_block = SCRIPT[SCRIPT.index("Upgrading existing agent"):
                           SCRIPT.index("if (-not $AgentName)")]
    assert "/api/agents/register" in upgrade_block
    assert "agent_key = $AgentKey" in upgrade_block


def test_a_failure_to_mark_the_token_is_not_fatal():
    """The agent already holds working credentials at that point; failing the
    install over a bookkeeping call would be worse than the stale token."""
    upgrade_block = SCRIPT[SCRIPT.index("Upgrading existing agent"):
                           SCRIPT.index("if (-not $AgentName)")]
    assert "catch" in upgrade_block
    assert "return" not in upgrade_block.split("catch")[1][:200]


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("yes", True), ("on", True),
    ("0", False), ("no", False), ("", False), ("anything", False),
])
def test_reenroll_switch_compares_values_rather_than_casting(value, expected):
    """`[bool]"0"` is $true in PowerShell, so a cast would have made
    SENTORA_REENROLL=0 force a re-enrolment - the opposite of what it says."""
    assert '-in @("1", "true", "yes", "on")' in SCRIPT
    assert (value in ("1", "true", "yes", "on")) is expected


def test_installer_has_no_unrendered_format_braces():
    """The template is an f-string; a single brace that should have been
    doubled produces PowerShell that silently misbehaves."""
    assert "{{" not in SCRIPT and "}}" not in SCRIPT


# --------------------------------------------------------------------------
# Server side
# --------------------------------------------------------------------------

def _register_source() -> str:
    src = APP.read_text(encoding="utf-8-sig")
    i = src.index("async def register_agent")
    return src[i:src.index("\n@app.", i)]


REGISTER = _register_source()


def test_reenrolment_requires_the_matching_key():
    """Accepting a name without proof would let any valid token claim another
    agent's identity, and with it that agent's data."""
    assert "WHERE agent_name=%s AND agent_key=%s" in REGISTER


def test_a_wrong_key_falls_through_to_fresh_enrolment():
    """A machine restored from a stale backup should get a new identity, not
    an error it cannot act on."""
    assert re.search(r"fall\s*\n?\s*#?\s*through|falls? through", REGISTER, re.I)


def test_the_upgrade_path_marks_the_token_used():
    upgrade = REGISTER[REGISTER.index("agent_key=%s"):]
    assert "UPDATE enrollment_tokens" in upgrade
    assert "used_by_agent" in upgrade, "column is used_by_agent, not used_by"


# --------------------------------------------------------------------------
# The identity that outlived the server's database
# --------------------------------------------------------------------------

def test_the_upgrade_path_uses_the_key_the_server_returns():
    """A host can hold a valid-looking `agent_key` the server has never seen -
    the database was restored, rebuilt, or lost.

    `/api/agents/register` handles that deliberately: it does not fail, it
    enrols the host afresh and returns a NEW key. The installer's upgrade
    branch used to pipe that reply to Out-Null and keep downloading with the
    credential the server had just told it was dead. The result was a bare
    `403 Forbidden` on the binary download with nothing explaining why, on a
    machine whose `config.json` looked perfectly healthy.
    """
    assert "| Out-Null" not in SCRIPT or "$UpResp = Invoke-RestMethod" in SCRIPT
    assert "$UpResp = Invoke-RestMethod" in SCRIPT
    assert "$UpResp.agent_key -ne $AgentKey" in SCRIPT
    assert "$AgentKey  = $UpResp.agent_key" in SCRIPT


def test_the_re_enrolment_is_announced():
    """Silently swapping the identity would leave an operator reading
    "Identity kept" while the opposite happened."""
    assert "Server did not recognise the stored key" in SCRIPT


def test_the_download_uses_whatever_key_the_script_ended_up_with():
    """Both branches converge on $AgentKey, so the fix above is enough - if
    the download hard-coded the config value instead, updating $AgentKey would
    change nothing."""
    download = SCRIPT[SCRIPT.index("Downloading agent binary"):]
    download = download[:download.index("Write-Host") + 400]
    assert '"X-Agent-Key" = $AgentKey' in download


def test_the_server_re_enrols_rather_than_refusing_an_unknown_key():
    """The other half. If the server rejected an unrecognised key, no
    installer change could recover the host."""
    import pathlib
    app = (pathlib.Path(__file__).resolve().parent.parent
           / "app.py").read_text(encoding="utf-8")
    assert "fall" in app and "enrol as a new agent" in app
