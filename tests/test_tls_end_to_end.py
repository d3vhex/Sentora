"""What only turning TLS on could have told us.

`tests/test_tls_serving.py` and `tests/test_ingest_tls.py` both passed against
a build where enabling TLS took the whole stack down. They were right about
every question they asked; they asked about the wrong layer. Three defects
survived them, and each needed a real container, a real certificate and a real
handshake to appear:

**The certificate could not be written.** `certs/` ships inside the image
owned by root, the server runs as `sentora`, and generation died with
`Permission denied: '/app/certs/rootCA.key'`. Refusing to fall back to plain
HTTP is correct, so the container restart-looped rather than serving something
weaker - the right behaviour turning a packaging mistake into an outage
instead of a silent downgrade. Generated material now lives in the data
volume, beside `data/fernet.key` and for the same reasons.

**The CA route read a path of its own.** `/api/agent/ca` looked in `certs/`
while the generator wrote to `TLS_DIR`, so the endpoint an installer depends
on for trust would have answered 404 on every containerised deployment.

**The control channel never received the CA.** `server_ca` reached the
telemetry socket and stopped there. Against a self-signed server the agent
shipped telemetry over TLS quite happily and could not open its channel at
all - and since the endpoint no longer listens on a port of its own, that is
an agent which reports and cannot be reached. Config, console, SOAR and the
screen stream all travel on that channel.

The pattern in all three: TLS is not one switch. It is a certificate that has
to be writable, discoverable by every process that needs it, and trusted by
both of the agent's connections. Any one of those missing produces a
deployment that looks encrypted from wherever you happen to be looking.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = ROOT / "docker-compose.yaml"
LINK = ROOT / "Sentora" / "modules" / "link.py"
MAIN = ROOT / "Sentora" / "main.py"

from core import tls  # noqa: E402


# --------------------------------------------------------------------------
# Where the material lives
# --------------------------------------------------------------------------

def test_the_material_directory_is_configurable():
    """It was hard-coded to `certs/`, which the container cannot write to."""
    assert tls.material_dir(env={"TLS_DIR": "/somewhere"}) == "/somewhere"


def test_it_defaults_to_the_checkout():
    """Unchanged for anyone running the server directly, which is also where
    `certs/generate_certs.py` writes when run by hand."""
    assert tls.material_dir(env={}).replace("\\", "/").endswith("/certs")


def test_the_reader_and_the_writer_agree():
    """`existing()` is what `ingest` uses to find what `app` generated. Two
    copies of the path is how the two come to disagree about where the
    certificate is - and the symptom is ingest reporting a missing
    certificate that is sitting right there."""
    env = {"TLS_ENABLED": "1", "TLS_DIR": "/somewhere"}
    source = (ROOT / "core" / "tls.py").read_text(encoding="utf-8")

    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "existing")
    assert "material_dir" in ast.unparse(fn)

    gen = next(n for n in ast.parse(source).body
               if isinstance(n, ast.FunctionDef) and n.name == "_generate")
    assert "material_dir" in ast.unparse(gen)

    # And nothing is found where nothing was written.
    assert tls.existing(env=env) is None


def test_generation_reports_an_unwritable_directory_by_name(tmp_path):
    """The bare errno gives no clue which of the two plausible causes it is,
    and they need opposite fixes: point TLS_DIR somewhere writable, or hand
    over a certificate somebody else manages.

    The unwritable path is a *file* with a directory path underneath it, which
    fails the same way on both platforms. The first version of this test used
    `/proc/nonexistent/certs`, which is unwritable on Linux and an ordinary
    relative path on Windows - so it created `C:\\proc\\nonexistent\\certs` and
    generated a real key inside it. A POSIX assumption in a test that exists to
    catch a filesystem-permission bug.
    """
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")

    with pytest.raises(tls.TLSConfigError) as excinfo:
        tls.resolve(env={"TLS_ENABLED": "1",
                         "TLS_DIR": str(blocker / "certs")},
                    log=lambda *_: None)
    assert "TLS_DIR" in str(excinfo.value)


def test_both_services_are_told_where_it_is():
    """A container path, so it belongs in compose - and on *both* services.
    On one only, ingest looks in /app/certs and reports a certificate that
    was never missing."""
    import yaml

    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    for service in ("app", "ingest"):
        env = compose["services"][service]["environment"]
        assert env.get("TLS_DIR"), f"{service} is not told where TLS material lives"
    assert (compose["services"]["app"]["environment"]["TLS_DIR"]
            == compose["services"]["ingest"]["environment"]["TLS_DIR"])


def test_the_material_lives_on_a_volume_the_server_owns():
    """`/app/certs` ships in the image owned by root and the server runs
    unprivileged. `/app/data` is the directory the Dockerfile chowns, which is
    why the Fernet key already lives there."""
    import yaml

    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    tls_dir = compose["services"]["app"]["environment"]["TLS_DIR"]
    mounts = compose["services"]["app"]["volumes"]
    assert any(m.split(":")[1] and tls_dir.startswith(m.split(":")[1])
               for m in mounts if ":" in m), (
        f"TLS_DIR={tls_dir} is not inside a mounted volume, so the "
        f"certificate is regenerated on every rebuild - which changes the "
        f"deployment's identity and stops every agent that trusted the old CA"
    )

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "chown -R sentora:sentora /app/data" in dockerfile, \
        "the directory TLS_DIR sits in is no longer prepared for the app user"


# --------------------------------------------------------------------------
# The CA has to be findable by the route that hands it out
# --------------------------------------------------------------------------

def test_the_ca_route_follows_the_same_directory():
    """It read `certs/rootCA.crt` directly while the generator wrote to
    TLS_DIR, so the endpoint an installer depends on for trust answered 404
    on every containerised deployment."""
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(app_py))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "download_ca")
    body = ast.unparse(fn)
    assert "ca_certificate" in body
    assert '"certs"' not in body and "'certs'" not in body


def test_the_ca_helper_never_reaches_for_the_key():
    """The distinction the design rests on: one half of the pair is meant to
    be distributed, the other signs everything this deployment vouches for."""
    source = (ROOT / "core" / "tls.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == "ca_certificate")
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    code = "\n".join(ast.unparse(n) for n in body)
    assert "rootCA.crt" in code
    assert "rootCA.key" not in code


# --------------------------------------------------------------------------
# Both of the agent's connections have to trust the same server
# --------------------------------------------------------------------------

def test_the_channel_accepts_a_ca():
    """Telemetry and control go to the same server over two connections. The
    CA reached one of them."""
    source = LINK.read_text(encoding="utf-8")
    init = source[source.index("    def __init__(self, server_url"):]
    init = init[:init.index("    # -- addressing")]
    assert "ca_cert" in init, "AgentLinkClient cannot be given a CA"

    serve = source[source.index("    def _serve_once"):]
    serve = serve[:serve.index("    def _send(")]
    assert "sslopt" in serve, "the CA is accepted and then not used"
    assert "ca_certs" in serve


def test_the_agent_hands_the_same_ca_to_both():
    """One `server_ca` for the host. Giving it to only the telemetry socket
    produced an agent that reported over TLS and was uncommandable - and with
    no listener on the endpoint any more, uncommandable is unreachable."""
    source = MAIN.read_text(encoding="utf-8")
    call = source[source.index("client = link.AgentLinkClient("):]
    call = call[:call.index(")\n")]
    assert "ca_cert=INGEST_CA" in call, (
        "the channel is constructed without the CA the telemetry socket uses"
    )


#: The functions that establish a connection the agent then trusts. Scoped to
#: these rather than the whole file, because one function deliberately does
#: not verify and must not be lumped in with them - see the test below.
CONNECTING_FUNCTIONS = [
    (MAIN, "_ingest_socket"),
    (LINK, "_serve_once"),
]


@pytest.mark.parametrize("path,name", CONNECTING_FUNCTIONS,
                         ids=[n for _, n in CONNECTING_FUNCTIONS])
def test_verification_is_never_switched_off_to_make_it_work(path, name):
    """The tempting fix when a handshake fails. An unverified TLS connection
    is encrypted to whoever answered, which against an attacker on the path is
    what not encrypting it would have achieved."""
    fn = next(n for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == name)
    body = ast.unparse(fn)
    for escape in ("CERT_NONE", "check_hostname = False",
                   "_create_unverified_context", "'cert_reqs': 0"):
        assert escape not in body, f"{name} disables verification ({escape})"


def test_the_one_unverified_handshake_carries_nothing():
    """`_explain_once_if_the_server_speaks_tls` deliberately does not verify,
    and that is correct: it asks "does anything here speak TLS", not "do I
    trust it", and the likeliest answer is a self-signed certificate it could
    not verify by definition.

    What makes it safe is that it sends nothing, reads nothing, and returns
    nothing to the caller - it exists to turn an unexplained reconnect loop
    into one line naming the cause. This pins that: the moment it starts
    carrying data it becomes an unverified connection like any other.
    """
    fn = next(n for n in ast.walk(ast.parse(LINK.read_text(encoding="utf-8")))
              if isinstance(n, ast.FunctionDef)
              and n.name == "_explain_once_if_the_server_speaks_tls")
    body = ast.unparse(fn)

    assert "CERT_NONE" in body, "the probe now verifies, so it cannot answer"
    for carries_data in ("send", "recv", "return raw", "self._ws"):
        assert carries_data not in body, (
            f"the diagnostic probe does {carries_data!r} on an unverified "
            f"connection; it may only observe that a handshake succeeds"
        )
