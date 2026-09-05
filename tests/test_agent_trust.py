"""One CA, trusted by everything the agent connects with.

`server_ca` is a statement about the host, and it was being wired in per
connection. That cost three fixes for one defect, each with a different
symptom and the same cause:

    the telemetry socket got it            - telemetry flowed over TLS
    the channel did not                    - reporting, and uncommandable
    the `requests` calls did not           - bootstrap failed, retrying for ever

The third only appeared when a real agent was pointed at a real TLS server:

    [!] Agent bootstrap attempt 1 failed: SSLError(SSLCertVerificationError(
        certificate verify failed: unable to get local issuer certificate))

Three per-connection fixes would have left a fourth client to find later, so
trust is installed once, before anything connects, where every client - and
anything added after this was written - picks it up.

The other half of the design is what the bundle contains. Pointing
`SSL_CERT_FILE` at the private CA *alone* would make the agent distrust every
other HTTPS endpoint on the machine to solve a problem with one of them, and
that failure would surface a long way from the line that caused it. So the
bundle is the system trust store plus this CA.
"""
from __future__ import annotations

import ast
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = ROOT / "Sentora" / "main.py"


def _install():
    """`_install_trust_bundle`, compiled on its own."""
    fn = next(n for n in ast.parse(MAIN.read_text(encoding="utf-8")).body
              if isinstance(n, ast.FunctionDef)
              and n.name == "_install_trust_bundle")
    namespace = {"os": os, "pathlib": pathlib, "print": lambda *a, **k: None}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(MAIN), "exec"),
         namespace)
    return namespace["_install_trust_bundle"]


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def ca(tmp_path):
    from certs.generate_certs import ensure_certs

    paths = ensure_certs(outdir=str(tmp_path), cn="soc.test", days=30,
                         log=lambda *_: None)
    return paths["root_crt"]


# --------------------------------------------------------------------------
# Every client, not one
# --------------------------------------------------------------------------

def test_all_three_variables_are_set(clean_env, ca):
    """`requests` reads the first two; `ssl.create_default_context()` with no
    cafile reads the third. Between them that is every client in the
    process."""
    bundle = _install()(ca)
    assert bundle
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"):
        assert os.environ.get(name) == bundle, f"{name} was not set"


def test_the_bundle_actually_verifies_that_ca(clean_env, ca, tmp_path):
    """The point of the file, checked by loading it the way a client does."""
    import ssl

    bundle = _install()(ca)
    context = ssl.create_default_context(cafile=bundle)
    assert context.get_ca_certs(), "the bundle contains no certificates"

    subjects = str(context.get_ca_certs())
    assert "Sentora-Local-RootCA" in subjects


def test_the_system_roots_survive(clean_env, ca):
    """The trap this avoids: trusting the private CA *instead of* everything
    else. The agent would then fail against any other HTTPS endpoint, a long
    way from the line that caused it."""
    certifi = pytest.importorskip("certifi")

    bundle = _install()(ca)
    written = pathlib.Path(bundle).read_bytes()
    system = pathlib.Path(certifi.where()).read_bytes()

    assert len(written) > len(system), \
        "the bundle is not larger than the system store, so it replaced it"
    assert system in written, "the system roots are not in the bundle"
    assert pathlib.Path(ca).read_bytes() in written, "the private CA is missing"


def test_no_ca_configured_changes_nothing(clean_env):
    """The overwhelmingly common deployment: a real certificate, and nothing
    to add. Writing a bundle anyway would be a file to go stale."""
    assert _install()(None) is None
    assert _install()("") is None
    assert os.environ.get("SSL_CERT_FILE") is None


def test_a_missing_ca_file_is_not_treated_as_one(clean_env, tmp_path):
    """`server_ca` pointing at a file that is not there is a real state - it
    happened during this migration - and it must not produce a bundle
    containing nothing."""
    assert _install()(str(tmp_path / "absent.crt")) is None
    assert os.environ.get("SSL_CERT_FILE") is None


def test_an_unwritable_location_falls_back(clean_env, ca, tmp_path, monkeypatch):
    """A read-only install directory is a real deployment. The bundle is
    derived rather than state, so a temp file is a correct answer."""
    import tempfile

    real_write = pathlib.Path.write_bytes
    install_dir = pathlib.Path(ca).parent

    def refuse(self, data):
        if self.parent == install_dir:
            raise OSError("read-only install directory")
        return real_write(self, data)

    monkeypatch.setattr(pathlib.Path, "write_bytes", refuse)
    bundle = _install()(ca)
    assert bundle, "a read-only install directory disabled trust entirely"
    assert bundle.startswith(tempfile.gettempdir())


# --------------------------------------------------------------------------
# It has to run before anything connects
# --------------------------------------------------------------------------

def test_trust_is_installed_before_the_first_connection():
    """Bootstrap is the first thing in the process to speak TLS, and it is
    what failed. Installing trust after it would fix nothing."""
    source = MAIN.read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = ast.unparse(fn)

    install_at = body.index("_install_trust_bundle")
    bootstrap_at = body.index("_init_agent_bootstrap")
    assert install_at < bootstrap_at, \
        "the agent connects before it knows what to trust"


def test_the_explicit_paths_are_kept_as_well():
    """Belt and braces on the two connections that matter most. The env
    variables cover every client; passing the CA directly means the telemetry
    socket and the channel do not depend on an environment variable surviving
    whatever else the process does to it."""
    source = MAIN.read_text(encoding="utf-8")
    assert "ca_cert=INGEST_CA" in source, "the channel lost its explicit CA"
    assert "cafile=INGEST_CA" in source, "the ingest socket lost its explicit CA"
