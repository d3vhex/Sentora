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
