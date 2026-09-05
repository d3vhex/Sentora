"""What the installer writes decides which transport an agent ever uses.

The Windows script wrote `ingest_port = 5001` into every config.json. The
agent derives its transport from `server_url` — an `https://` console means
telemetry goes to the TLS listener — and an explicit port overrides that
derivation, by design, so somebody forwarding through a bastion can say what
they mean.

Those two facts together meant every Windows agent would have stayed on the
plaintext port for ever, against a server configured for TLS, with nothing
anywhere reporting a problem: the telemetry arrives, the console fills, and
the only difference is that it crossed the network in the clear. That is the
shape of failure this codebase keeps finding, and a config file is a
particularly good place to hide it, because it is written once at enrolment
and then never looked at again.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

from core.installers import _render_linux_install, _render_windows_install  # noqa: E402


@pytest.fixture(params=["https://soc.example.com:8000", "http://10.0.0.5:8000"])
def url(request):
    return request.param


def _linux(url: str) -> str:
    return _render_linux_install(url, "10.0.0.5", "tok-123")


def _windows(url: str) -> str:
    return _render_windows_install(url, "10.0.0.5", "tok-123")


# --------------------------------------------------------------------------
# The port the agent is left on
# --------------------------------------------------------------------------

def test_no_installer_pins_the_ingest_port(url):
    """Pinning it defeats the derivation from `server_url`, which is the only
    thing that moves a fleet onto TLS without a second setting to get wrong."""
    for name, script in (("linux", _linux(url)), ("windows", _windows(url))):
        assert not re.search(r"ingest_port\s*[=:]\s*5001", script), (
            f"the {name} installer pins ingest_port, so this agent will stay "
            f"on the plaintext listener whatever the server is configured to do"
        )


def test_the_config_still_carries_what_the_agent_needs(url):
    """A guard against fixing the above by deleting too much: the identity
    fields are what the agent refuses to start without."""
    for script in (_linux(url), _windows(url)):
        for field in ("agent_name", "agent_key", "server_url"):
            assert field in script


# --------------------------------------------------------------------------
# Trusting a self-signed server
# --------------------------------------------------------------------------

def test_an_https_installer_fetches_the_ca(url):
    """Against a self-signed server the agent verifies and therefore fails,
    which is correct — an unverified TLS connection is encrypted to whoever
    answered. Something has to put the CA on the endpoint, and the installer
    is the only step that runs there with the server reachable."""
    for script in (_linux(url), _windows(url)):
        assert "/api/agent/ca" in script
        assert "server_ca" in script


def test_the_ca_fetch_is_conditional_on_https():
    """Against plain http there is nothing to verify, and against a real CA
    the endpoint's trust store already has it. Writing an empty server_ca
    unconditionally would be harmless; fetching unconditionally would put a
    404 body on disk and fail later with a certificate-format error far from
    the cause."""
    linux = _linux("http://10.0.0.5:8000")
    assert "https://*" in linux, "the linux fetch is not gated on the scheme"

    windows = _windows("http://10.0.0.5:8000")
    assert '$ServerUrl -like "https://*"' in windows


def test_an_empty_ca_file_is_not_kept():
    """A zero-byte PEM is worse than none: it satisfies every existence check
    and fails at the point of use."""
    linux = _linux("https://soc.example.com")
    assert "-s " in linux and "rm -f" in linux
    windows = _windows("https://soc.example.com")
    assert ".Length -gt 0" in windows


# --------------------------------------------------------------------------
# The endpoint it fetches from
# --------------------------------------------------------------------------

def _download_ca_code() -> str:
    """The handler's statements, with its docstring dropped.

    Its docstring names the file it exists to never serve, so matching the raw
    source finds the explanation and reads it as the code. That mistake has
    been made repeatedly in this suite; the fix is always to assert on the
    parsed body rather than the text.
    """
    import ast

    tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "download_ca")
    body = list(fn.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


def test_the_server_serves_the_certificate_and_never_the_key():
    """The distinction the whole design rests on. One half of the pair is
    meant to be distributed; the other signs everything this deployment
    vouches for."""
    code = _download_ca_code()
    assert "rootCA.crt" in code
    assert "rootCA.key" not in code


def test_the_ca_route_is_public_deliberately():
    """An installer needs it before it holds any credential. Listed rather
    than left to the path backstop, so `test_auth_wiring` sees a decision
    instead of an omission."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    handlers = app_py[app_py.index("_PUBLIC_HANDLERS = {"):]
    handlers = handlers[:handlers.index("\n}")]
    assert '"download_ca"' in handlers


def test_a_server_with_no_local_ca_says_so():
    """404, not an empty body. A deployment using a real certificate has no
    local CA and needs none, and that answer has to be distinguishable from a
    broken one."""
    assert "status=404" in _download_ca_code()


# --------------------------------------------------------------------------
# The scripts still have to be scripts
# --------------------------------------------------------------------------

def test_the_linux_script_has_no_unexpanded_template_braces(url):
    """`_render_*` are f-strings, so a literal brace has to be doubled. One
    that is not becomes a KeyError at render time, or worse, silently
    interpolates something."""
    script = _linux(url)
    assert "{{" not in script and "}}" not in script


def test_the_windows_script_has_no_unexpanded_template_braces(url):
    script = _windows(url)
    assert "{{" not in script and "}}" not in script


def test_the_written_config_is_valid_json():
    """The heredoc is assembled by hand, and a missing comma between two
    fields is a config the agent refuses to load — on the endpoint, after the
    installer has reported success."""
    script = _linux("https://soc.example.com:8000")
    body = script[script.index('cat > "$INSTALL_DIR/config.json"'):]
    body = body[body.index("{"):body.index("EOF\n", body.index("{"))]

    # Shell variables stand in for values; substitute something JSON-safe.
    literal = re.sub(r"\$[A-Z_]+", "x", body).strip()
    json.loads(literal)


# --------------------------------------------------------------------------
# Enrolment has to be possible in the first place
# --------------------------------------------------------------------------

def test_trust_is_established_before_the_first_network_call():
    """The CA was fetched at the *end* of both installers, after registration
    and after the binary download.

    Against a self-signed server every one of those calls failed first, and
    the CA that would have fixed them arrived two steps too late:

        iwr : Temel alinan baglanti kapatildi: SSL/TLS guvenli kanali icin
              guven iliskisi kurulamadi.

    So enrolment - the one path a machine with no Sentora on it has to walk -
    was impossible the moment TLS was turned on.
    """
    for name, script in (("linux", _linux("https://soc.example.com")),
                         ("windows", _windows("https://soc.example.com"))):
        ca_at = script.index("/api/agent/ca")
        register_at = script.index("/api/agents/register")
        download_at = script.index("/api/agent/download/")
        assert ca_at < register_at, f"{name} registers before it trusts anything"
        assert ca_at < download_at, f"{name} downloads before it trusts anything"


def test_the_rest_of_the_install_verifies():
    """The exception is for one request. Every call after it has the CA
    available and must use it - otherwise the bypass has quietly become the
    transport."""
    linux = _linux("https://soc.example.com")
    for call in ("/api/agents/register", "/api/agent/download/linux"):
        line = next(l for l in linux.splitlines() if call in l)
        assert "$CURL_CA" in line, f"{call} does not verify the server"

    windows = _windows("https://soc.example.com")
    assert r"Cert:\LocalMachine\Root" in windows, (
        "the Windows installer never installs the CA, so every later call - "
        "and any browser on the host - still cannot verify the console"
    )


def test_the_bypass_leaves_nothing_behind():
    """The first version restored a static `ServerCertificateValidationCallback`
    in a `finally`, which was the right instinct about the wrong mechanism -
    that callback cannot work on PS 5.1 at all (see below).

    `curl.exe` needs no restoring: the exception lives and dies with a child
    process, so nothing in the PowerShell session is left unverified. This
    pins that property rather than the old ceremony - if the fetch ever moves
    back in-process, it has to reintroduce the restore too.
    """
    code = _executable(_windows("https://soc.example.com"))
    fetch = code[code.index("$CaPath = Join-Path"):]
    fetch = fetch[:fetch.index("Import-Certificate")]

    assert "curl.exe" in fetch, "the first-contact fetch is in-process again"
    assert "ServicePointManager" not in fetch, (
        "process-wide TLS state is being changed; if that is deliberate it "
        "has to be restored, and a script-block callback still will not work"
    )


def test_no_bypass_when_there_is_nothing_to_bypass():
    """An http:// server has no certificate to distrust, and adding `-k`
    there would be a habit that outlives the reason for it."""
    linux = _linux("http://10.0.0.5:8000")
    assert "curl -fsSk" not in linux.split("case \"$SERVER_URL\"")[0]


@pytest.mark.parametrize("scheme,self_signed,expect_bypass", [
    ("https", True, True),      # our own CA: nothing trusts it yet
    ("https", False, False),    # a real certificate: the snippet must stay clean
    ("http", True, False),      # no TLS at all
])
def test_the_console_hands_out_a_command_that_can_run(scheme, self_signed, expect_bypass):
    """The one-liner is the first thing a new host runs, and it was emitted
    without regard to whether anything could verify the server."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    block = app_py[app_py.index('"install": {') - 3000:app_py.index('"install": {')]
    assert "ca_certificate()" in block, (
        "the enrolment snippet is built without checking whether this server "
        "signs with its own CA"
    )
    assert 'proto == "https"' in block, \
        "the snippet would carry a TLS exception on a plain-http server"


# --------------------------------------------------------------------------
# The bypass has to actually run
# --------------------------------------------------------------------------

def _executable(script: str) -> str:
    """The script with its comment lines stripped.

    The comments here warn about the exact construct they name, so matching
    the raw text finds the warning and reads it as the code. That has now
    caught seven tests in this suite.
    """
    return "\n".join(line for line in script.splitlines()
                     if not line.strip().startswith("#"))


def test_no_script_block_is_used_as_a_certificate_callback():
    """`ServerCertificateValidationCallback = {$true}` is the form everyone
    reaches for, and on PowerShell 5.1 it does not work.

    .NET invokes the callback on an I/O thread that has no runspace, so the
    script block itself throws:

        PSInvalidOperationException: There is no Runspace available to run
        scripts in this thread. The script block you attempted to invoke
        was: $true

    What the operator sees is "an unexpected error occurred on a send", which
    reads as a TLS failure. An hour went into protocol versions, cipher
    suites, ALPN and IPv6 before the inner exception was unwrapped. Any fix
    here has to be a compiled type or an out-of-process client - never a
    script block.
    """
    code = _executable(_windows("https://soc.example.com"))
    assert "ServerCertificateValidationCallback" not in code, (
        "the installer sets a certificate callback again; on PS 5.1 a script "
        "block there fails on a thread with no runspace"
    )


def test_the_first_contact_fetch_runs_out_of_process():
    """`curl.exe` ships with Windows 10 1803 and later, has no runspace to
    lose, and confines the exception to one request with no static state left
    behind for the rest of the session."""
    code = _executable(_windows("https://soc.example.com"))
    assert "curl.exe -fsSk" in code

    missing = _executable(_windows("https://soc.example.com"))
    assert "Get-Command curl.exe" in missing, (
        "nothing says what to do on a Windows old enough to lack curl.exe"
    )


def test_the_console_snippet_avoids_the_same_trap():
    """The one-liner is the first thing anybody runs, and it had the same
    broken callback in it."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    block = app_py[app_py.index("self_signed = product_tls.ca_certificate()"):]
    block = block[:block.index('"install": {')]
    executable = "\n".join(l for l in block.splitlines()
                           if not l.strip().startswith("#"))
    assert "ServerCertificateValidationCallback" not in executable
    assert "curl.exe -fsSk" in executable
