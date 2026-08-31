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


# --------------------------------------------------------------------------
# The Linux installer left the agent without a database
# --------------------------------------------------------------------------

from core.installers import _render_linux_install  # noqa: E402

LINUX = _render_linux_install("http://example:8000", "203.0.113.1", "TOKEN")


def test_the_rendered_linux_installer_is_valid_bash():
    """The installer is piped straight into `bash` by whoever runs the deploy
    command, so a syntax error here is a syntax error on their machine."""
    import shutil
    import subprocess

    if shutil.which("bash") is None:
        pytest.skip("no bash on PATH")
    result = subprocess.run(["bash", "-n"], input=LINUX.encode("utf-8"),
                            capture_output=True)
    # Shared with test_build_agent_sh, which is where the reasoning lives:
    # the `bash` on PATH here is usually the WSL shim, and a WSL that will not
    # start exits non-zero with its own complaint on stdout and stderr empty.
    # Read as a failure, that says the installer is broken shell.
    from test_build_agent_sh import _assert_bash_accepted
    _assert_bash_accepted(result, "the rendered Linux installer")


def test_it_has_no_unrendered_format_braces():
    """The template is an f-string. A single brace that should have been
    doubled produces shell that is subtly wrong rather than obviously so."""
    assert "{{" not in LINUX
    assert "}}" not in LINUX


def test_docker_is_installed_because_the_database_needs_it():
    """The agent keeps its state in a local postgres shipped as
    docker-compose.yml inside the download. Without Docker the binary starts,
    cannot reach 127.0.0.1:5432, and systemd restarts it forever - while the
    installer has already printed "installed and running".

    Observed on a fresh EC2 box: green install, no agent in the console, and
    `docker: command not found`."""
    assert "command -v docker" in LINUX
    assert "apt-get install -y docker.io" in LINUX


def test_the_database_is_started_before_the_service():
    """Starting the agent first means it crash-loops until postgres happens to
    be ready, filling the journal with errors that describe a race rather than
    the actual state."""
    db_at = LINUX.index("docker compose up -d")
    service_at = LINUX.index("systemctl restart sentora-agent")
    assert db_at < service_at


def test_it_waits_for_postgres_rather_than_hoping():
    assert "pg_isready" in LINUX
    assert "did not become ready" in LINUX


def test_a_database_that_never_comes_up_stops_the_install():
    """An agent that cannot reach its database reports nothing, and an install
    that claims success while that is true is worse than one that stops."""
    block = LINUX[LINUX.index("Waiting for postgres"):]
    block = block[:block.index("SERVICE_FILE=")]
    assert "exit 1" in block


def test_the_unit_orders_itself_after_docker():
    """After a reboot the agent would otherwise start before its database and
    spend RestartSec cycles failing."""
    assert "After=network-online.target docker.service" in LINUX
    assert "Requires=docker.service" in LINUX


def test_success_is_verified_rather_than_announced():
    """`systemctl restart` returns success once systemd has forked the
    process. A binary that exits immediately still leaves the installer
    printing "installed and running"."""
    assert "systemctl is-active --quiet sentora-agent" in LINUX
    tail = LINUX[LINUX.index("systemctl is-active"):]
    assert "journalctl -u sentora-agent" in tail


def test_the_windows_installer_still_brings_its_database_up():
    """It always did - this whole fix is the Linux side catching up, and the
    two must not drift apart again."""
    assert "docker compose up -d" in SCRIPT
    assert "sentora-db-agent" in SCRIPT


def test_compose_is_installed_separately_from_docker():
    """`docker.io` is the daemon and nothing else. Compose v2 is a separate
    package on Debian and Ubuntu, so installing Docker alone leaves
    `docker compose` unavailable - and the failure arrives later, when the
    database is meant to start, reported as a Docker problem."""
    assert "docker compose version" in LINUX
    assert "docker-compose-v2" in LINUX


def test_no_compose_at_all_stops_the_install():
    """The agent's database is defined as a compose file. Without a compose
    implementation there is nothing to bring it up with."""
    block = LINUX[LINUX.index("No Docker Compose available"):]
    assert "exit 1" in block[:400]


def test_the_agents_database_is_not_published_to_the_world():
    """`5432:5432` binds 0.0.0.0. On a cloud VM that puts the agent's postgres
    on the public interface behind nothing but the hardcoded credentials in
    the same file - and it holds everything the agent has collected about the
    host.

    The agent connects to 127.0.0.1 (modules/db.py DB_HOST), so the wider bind
    was never buying anything.
    """
    import pathlib
    compose = (pathlib.Path(__file__).resolve().parent.parent
               / "Sentora" / "docker-compose.yml").read_text(encoding="utf-8")
    published = [l.strip() for l in compose.splitlines()
                 if l.strip().startswith('- "') and ":5432" in l]
    assert published, "the port mapping disappeared"
    for line in published:
        assert line.startswith('- "127.0.0.1:'), line


# --------------------------------------------------------------------------
# The installer closes the agent port instead of opening it
# --------------------------------------------------------------------------
#
# The agent used to listen on 0.0.0.0:9099 and the server called it there for
# config reads, SOAR dispatch and the screen stream, so both installers opened
# an inbound hole for it. Windows blocks inbound connections to a program that
# has not been allowed, and the prompt that normally asks cannot appear for a
# SYSTEM process in session 0 - so the port stayed shut with nothing saying so,
# and every call in returned `Connection refused` against a listening process.
#
# The agent now opens the connection itself and the server answers over it.
# Nothing reaches in, the listener binds to loopback, and the rule has nothing
# left to permit.

def _windows_script() -> str:
    from core import installers
    return installers._render_windows_install(
        "http://sentora.example", "10.0.0.1", "t" * 64)


def test_the_windows_installer_opens_no_inbound_rule():
    """An open management port on every endpoint, kept alive by history."""
    script = _windows_script()
    assert "New-NetFirewallRule" not in script


def test_the_windows_installer_removes_an_older_one():
    """Not creating the rule is not enough: a host installed by an earlier
    build still has the hole, and an upgrade that steps over it leaves the
    port open on nothing but the fact that it used to be needed."""
    script = _windows_script()
    assert "Remove-NetFirewallRule" in script
    assert "Sentora Agent API" in script


def test_a_failed_removal_is_reported_not_swallowed():
    """Nothing breaks if it fails, which is exactly why it has to be said out
    loud - the host is left more open than this build intends, and only
    someone reading that line will know to close it."""
    script = _windows_script()
    assert "Could not remove the old firewall rule" in script


def test_uninstall_removes_the_rule():
    """A hole named after software that is no longer installed is not
    something anyone goes looking for later."""
    main = (pathlib.Path(__file__).resolve().parent.parent
            / "Sentora" / "main.py").read_text(encoding="utf-8")
    assert "Remove-NetFirewallRule" in main


# --------------------------------------------------------------------------
# The same on Linux
# --------------------------------------------------------------------------
#
# Both installers opened the port and both now close it. The asymmetry that
# existed before - Windows opening it while a ufw host silently dropped every
# call - was an accident, and so would be fixing only one of them now.

def _linux_script() -> str:
    from core import installers
    return installers._render_linux_install(
        "http://sentora.example", "10.0.0.1", "t" * 64)


def test_the_linux_installer_opens_no_inbound_rule():
    script = _linux_script()
    assert "ufw allow from" not in script


def test_the_linux_installer_removes_an_older_one():
    """Same reason as Windows: the hole outlives the need for it."""
    script = _linux_script()
    assert "ufw delete allow from" in script
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert net in script, f"{net} would be left allowed"


def test_it_only_touches_a_firewall_that_is_running():
    """Running `ufw` on a host that does not use it is noise in someone
    else's configuration - and `ufw status` on an inactive firewall says
    nothing useful to grep."""
    script = _linux_script()
    assert "command -v ufw" in script
    assert "Status: active" in script


def test_a_rule_left_behind_is_reported_not_assumed():
    """A rule this installer did not add can still be allowing 9099. Nothing
    breaks, so nothing else will ever mention it."""
    script = _linux_script()
    assert "Inbound 9099 is still allowed" in script


def test_the_installer_scripts_stay_lf_only():
    """CRLF in a shell script breaks bash on Linux, and the installer is piped
    straight into it."""
    assert "\r" not in _linux_script()
