"""Telemetry over TLS, and a migration that is visible rather than silent.

Ingest carried every log line, process name, path and hostname the fleet
produces, in the clear, on a port published on all interfaces. The console got
TLS first because a login form is the obvious thing to protect; the larger and
more sensitive stream was the one nobody looked at.

Two design decisions are worth pinning here, because both are easy to
"simplify" back into a bug.

**Two ports, not a flag on one.** The existing protocol opens with a 4-byte
big-endian length, so its first byte is always 0x00; a TLS ClientHello opens
with 0x16. They are trivially distinguishable - but distinguishing them means
reading a byte that then cannot be handed back to the TLS layer, so one port
can serve one of them and not both.

**The plaintext listener stays open until it is closed deliberately.** Cutting
straight to TLS would blackhole every agent built before this, and a host that
stopped reporting looks exactly like a host with nothing to report. That is
the failure this codebase keeps finding. So the plaintext port keeps working,
names the agents still using it, and `INGEST_TLS_REQUIRED=1` closes it once
the fleet has moved.
"""
from __future__ import annotations

import ast
import pathlib
import socket
import ssl

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server.py"
MAIN = ROOT / "Sentora" / "main.py"


def _function(path: pathlib.Path, name: str) -> ast.AST:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return next(n for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == name)


# --------------------------------------------------------------------------
# The server opens the right listeners
# --------------------------------------------------------------------------

def test_both_listeners_exist():
    body = ast.unparse(_function(SERVER, "main"))
    assert "INGEST_TLS_PORT" in body
    assert "SERVER_PORT" in body
    assert "ssl=tls_context" in body, "the TLS listener is not actually encrypted"


def test_the_plaintext_listener_can_be_closed():
    """The migration has to be able to end. A permanent plaintext port is a
    permanent way to bypass the encrypted one."""
    body = ast.unparse(_function(SERVER, "main"))
    assert "INGEST_TLS_REQUIRED" in body


def test_requiring_tls_without_configuring_it_is_a_startup_failure():
    """`INGEST_TLS_REQUIRED=1` with `TLS_ENABLED` unset would close the
    plaintext port and open nothing - an ingest service listening on nothing
    at all, which from the fleet's side is indistinguishable from a quiet
    week."""
    body = ast.unparse(_function(SERVER, "main"))
    guard = body[body.index("INGEST_TLS_REQUIRED"):]
    assert "SystemExit" in guard


def test_tls_that_cannot_be_served_is_not_downgraded():
    """The same rule the console follows. Telemetry is the more sensitive of
    the two streams, so falling back to the plaintext port would be the worse
    half of the deployment quietly continuing."""
    body = ast.unparse(_function(SERVER, "main"))
    handler = next(h for h in ast.walk(_function(SERVER, "main"))
                   if isinstance(h, ast.ExceptHandler)
                   and "cannot be served" in ast.unparse(h))
    assert "SystemExit" in ast.unparse(handler)
    assert "start_server" not in ast.unparse(handler)
    assert body.count("SystemExit") >= 2


def test_a_plaintext_agent_is_named_once_not_counted_forever():
    """'Nine agents are still in the clear' is a number an operator can act
    on. Forty thousand connection warnings is a log nobody reads."""
    body = ast.unparse(_function(SERVER, "handle_client"))
    assert "PLAINTEXT_AGENTS" in body
    assert "in the clear" in body

    source = SERVER.read_text(encoding="utf-8")
    assert "PLAINTEXT_AGENTS: set[str] = set()" in source, \
        "a set, so the same agent is reported once rather than per batch"


def test_the_server_does_not_refuse_plaintext_mid_connection():
    """Refusing here would drop the batch after the agent had already
    committed to sending it, with the explanation on the wrong machine.
    Closing the port is the honest refusal: a connection refused is a symptom
    an operator can see."""
    fn = _function(SERVER, "handle_client")
    body = ast.unparse(fn)
    guard = body[body.index("PLAINTEXT_AGENTS"):]
    head = guard[:guard.index("await insert_data")] if "await insert_data" in guard else guard
    assert "return" not in head.split("print")[0]


# --------------------------------------------------------------------------
# The agent picks the same transport without being told twice
# --------------------------------------------------------------------------

def _resolve():
    """`_resolve_ingest_transport`, compiled with the constants it names."""
    import os as _os

    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef)
              and n.name == "_resolve_ingest_transport")
    referenced = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    constants = [n for n in tree.body
                 if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in referenced for t in n.targets)]

    namespace: dict = {"os": _os}
    exec(compile(ast.Module(body=[*constants, fn], type_ignores=[]),
                 str(MAIN), "exec"), namespace)
    return namespace["_resolve_ingest_transport"]


class _Args:
    def __init__(self, ingest_port=None, ca=None):
        self.ingest_port = ingest_port
        self.ca = ca


def test_https_implies_encrypted_telemetry():
    """Derived from `server_url`, the rule `modules/link.channel_url` already
    uses for the control channel. Two settings that have to agree, with
    nothing making them agree, would be wrong in exactly the deployment that
    believed it was encrypted."""
    tls, port, _, host = _resolve()({"server_url": "https://soc.example.com:8000"}, _Args())
    assert tls is True
    assert port == 5011
    assert host == "soc.example.com"


def test_http_stays_on_the_plaintext_port():
    """A lab pointed at http:// must keep working exactly as it did."""
    tls, port, _, _ = _resolve()({"server_url": "http://127.0.0.1:8000"}, _Args())
    assert tls is False
    assert port == 5001


def test_an_explicit_port_still_wins():
    """Somebody forwarding through a bastion has a real reason to override
    this, so the derivation is a default rather than a rule."""
    _, port, _, _ = _resolve()({"server_url": "https://soc.example.com"},
                               _Args(ingest_port=7001))
    assert port == 7001


def test_the_certificate_name_comes_from_the_url_not_the_address():
    """`certs/generate_certs.py` puts a hostname in the SAN. Verifying an IP
    against it fails with a message that reads like a certificate problem when
    it is an addressing one."""
    _, _, _, host = _resolve()({"server_url": "https://soc.example.com:8000/"}, _Args())
    assert host == "soc.example.com"


def test_a_ca_path_that_does_not_exist_is_reported_not_ignored(capsys, tmp_path):
    """Silently falling back to the system trust store gives a connection that
    fails later for a reason that has nothing to do with the real cause."""
    _, _, ca, _ = _resolve()(
        {"server_url": "https://soc.example.com", "server_ca": str(tmp_path / "absent.pem")},
        _Args())
    assert ca is None
    assert "does not exist" in capsys.readouterr().out


def test_a_real_ca_path_is_kept(tmp_path):
    bundle = tmp_path / "rootCA.crt"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    _, _, ca, _ = _resolve()(
        {"server_url": "https://soc.example.com", "server_ca": str(bundle)}, _Args())
    assert ca == str(bundle)


# --------------------------------------------------------------------------
# The connection the agent actually makes
# --------------------------------------------------------------------------

def test_the_agent_verifies_the_server_certificate():
    """An unverified TLS connection is encrypted to whoever answered, which
    against an attacker on the path is what not encrypting it would have
    achieved. `create_default_context` verifies; the ways to turn that off are
    what this guards against."""
    body = ast.unparse(_function(MAIN, "_ingest_socket"))
    assert "create_default_context" in body
    assert "server_hostname" in body
    assert "CERT_NONE" not in body
    assert "check_hostname = False" not in body
    assert "_create_unverified_context" not in body


def test_the_ingest_socket_has_a_timeout():
    """An unbounded blocking read is how a collector thread disappears for
    good - and a thread that never returns reports nothing and looks like a
    quiet host."""
    body = ast.unparse(_function(MAIN, "_ingest_socket"))
    assert "settimeout" in body


def test_a_failed_handshake_does_not_leak_the_socket():
    """`wrap_socket` raising leaves the underlying descriptor open. One per
    cycle is a file-descriptor leak that ends as a host that stops reporting
    for reasons nothing explains."""
    fn = _function(MAIN, "_ingest_socket")
    handler = next(h for h in ast.walk(fn) if isinstance(h, ast.ExceptHandler))
    assert "close" in ast.unparse(handler)
    assert "raise" in ast.unparse(handler)


# --------------------------------------------------------------------------
# One TLS identity for the deployment
# --------------------------------------------------------------------------

def test_ingest_shares_the_consoles_certificate_settings():
    """A second pair of certificate variables is a second thing to rotate and
    a second thing to forget. It is also the only arrangement an agent can be
    told to trust in one step."""
    body = ast.unparse(_function(SERVER, "_ingest_tls_context"))
    assert "product_tls" in body or "core import tls" in body
    assert "TLS_INGEST_CERT" not in SERVER.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# An actual handshake
# --------------------------------------------------------------------------

def test_the_agent_can_reach_a_tls_listener_end_to_end(tmp_path):
    """The one test that would have caught the bug this work started from.

    Everything above reads source. Source can be entirely correct about a
    feature that does not work - `TLS_ENABLED` was documented in three places
    and wired to nothing, and no amount of reading the documentation would
    have revealed it. So this one runs a real listener with a real generated
    certificate and makes the agent's own connect path talk to it.
    """
    import ssl as _ssl
    import threading

    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="localhost", days=30,
                         log=lambda *_: None)

    server_ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(certfile=paths["crt"], keyfile=paths["key"])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    seen: dict = {}

    def serve():
        raw, _ = listener.accept()
        try:
            with server_ctx.wrap_socket(raw, server_side=True) as tls:
                seen["received"] = tls.recv(16)
                tls.sendall(b"pong")
        except Exception as e:          # pragma: no cover - surfaced below
            seen["error"] = f"{type(e).__name__}: {e}"
        finally:
            raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    connect = _compiled_socket_fn(
        SERVER_IP="127.0.0.1", SERVER_PORT=port, INGEST_TLS=True,
        INGEST_CA=paths["root_crt"], SERVER_HOSTNAME="localhost")

    with connect() as sock:
        sock.sendall(b"ping")
        assert sock.recv(16) == b"pong"

    thread.join(timeout=5)
    assert seen.get("error") is None, seen.get("error")
    assert seen.get("received") == b"ping"


def test_a_server_the_agent_cannot_verify_is_refused(tmp_path):
    """The other half, and the one that is easy to lose. Encryption to an
    unverified peer is encryption to whoever answered - against an attacker on
    the path, exactly what not encrypting it would have achieved."""
    import ssl as _ssl
    import threading

    from certs.generate_certs import ensure_certs

    real = ensure_certs(outdir=str(tmp_path / "server"), cn="localhost",
                        days=30, log=lambda *_: None)
    stranger = ensure_certs(outdir=str(tmp_path / "other"), cn="localhost",
                            days=30, log=lambda *_: None)

    server_ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(certfile=real["crt"], keyfile=real["key"])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        try:
            raw, _ = listener.accept()
            try:
                server_ctx.wrap_socket(raw, server_side=True)
            except Exception:
                pass
            finally:
                raw.close()
        except Exception:
            pass

    threading.Thread(target=serve, daemon=True).start()

    # Handed the wrong CA: a different deployment's, which is what an attacker
    # presenting their own certificate looks like from here.
    connect = _compiled_socket_fn(
        SERVER_IP="127.0.0.1", SERVER_PORT=port, INGEST_TLS=True,
        INGEST_CA=stranger["root_crt"], SERVER_HOSTNAME="localhost")

    with pytest.raises(ssl.SSLError):
        connect()


def _compiled_socket_fn(**globals_):
    """`_ingest_socket`, compiled with the module globals it reads replaced."""
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_ingest_socket")

    # The module-level constants it reads, lifted with it. Compiling the
    # function alone raises NameError on the first one, which reads as a bug
    # in the agent rather than in the harness.
    tree_body = ast.parse(MAIN.read_text(encoding="utf-8")).body
    referenced = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    constants = [n for n in tree_body
                 if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in referenced for t in n.targets)]

    namespace: dict = {"socket": socket, "ssl": ssl}
    exec(compile(ast.Module(body=[*constants, fn], type_ignores=[]),
                 str(MAIN), "exec"), namespace)
    # After the constants, so the test's values win over the shipped defaults.
    namespace.update(globals_)
    return namespace["_ingest_socket"]
