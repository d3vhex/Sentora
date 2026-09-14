"""Unit tests for the OSV vulnerability scanner.

Focused on the deterministic helpers — ecosystem detection, dedup
fingerprinting, Debianish version normalisation, and the offline behaviour
when OSV is unreachable. The HTTP-fronted call paths are exercised via
mocked `requests.post` / `requests.get`.
"""
from __future__ import annotations

import pytest

from scanners import vuln



def test_dup_fp_is_stable_for_same_inputs():
    a = vuln._make_dup_fp("openssl", "1.1.1f-1ubuntu2", "CVE-2024-0001")
    b = vuln._make_dup_fp("openssl", "1.1.1f-1ubuntu2", "CVE-2024-0001")
    assert a == b
    assert len(a) == 64


def test_dup_fp_differs_on_version_change():
    a = vuln._make_dup_fp("openssl", "1.1.1f-1ubuntu2", "CVE-2024-0001")
    b = vuln._make_dup_fp("openssl", "1.1.1g-1ubuntu1", "CVE-2024-0001")
    assert a != b


def test_dup_fp_differs_on_cve_change():
    a = vuln._make_dup_fp("openssl", "1.1.1f-1ubuntu2", "CVE-2024-0001")
    b = vuln._make_dup_fp("openssl", "1.1.1f-1ubuntu2", "CVE-2024-0002")
    assert a != b



@pytest.mark.parametrize(
    "raw,expected_norm,expected_upstream",
    [
        ("4:13.2.0-7ubuntu1", "13.2.0-71", "13.2.0"),
        ("1.21.2-2ubuntu1.1", "1.21.2-21.1", "1.21.2"),
        ("5.2.5-2ubuntu1", "5.2.5-21", "5.2.5"),
        ("2:8.2.3995", "8.2.3995", "8.2.3995"),
        ("", "", ""),
    ],
)
def test_normalize_debianish_version(raw, expected_norm, expected_upstream):
    norm, upstream = vuln._normalize_debianish_version(raw)
    assert norm == expected_norm
    assert upstream == expected_upstream



@pytest.mark.parametrize(
    "os_info,expected",
    [
        ("Windows-11-10.0.26200-SP0", "Windows"),
        ("Linux-5.15.0-91-generic-x86_64-with-glibc2.35 ubuntu 22.04", "Debian"),
        ("Debian GNU/Linux 12 (bookworm)", "Debian"),
        ("CentOS Linux 7 (Core) rhel-derived", "RPM"),
        ("Fedora Linux 39", "RPM"),
        ("Alpine Linux 3.18", "Alpine"),
        ("Arch Linux", "ARCH"),
        ("Manjaro Linux", "ARCH"),
        (None, None),
        ("", None),
        ("Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.35", None),
    ],
)
def test_detect_ecosystem_string_only(os_info, expected):
    assert vuln._detect_ecosystem(os_info) == expected


def test_detect_ecosystem_wsl_fingerprints_to_debian_via_packages():
    """WSL Ubuntu reports a generic kernel string. The fallback inspects
    package version patterns to recover the ecosystem."""
    os_info = "Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.35"
    pkgs = [
        {"package": "openssl", "version": "1.1.1f-1ubuntu2.20"},
        {"package": "vim", "version": "2:8.2.3995-1ubuntu2.21"},
    ]
    assert vuln._detect_ecosystem(os_info, pkgs) == "Debian"


def test_detect_ecosystem_unknown_linux_defaults_to_debian():
    os_info = "Linux-some-weird-thing"
    pkgs = [{"package": "x", "version": "1.0"}]
    assert vuln._detect_ecosystem(os_info, pkgs) == "Debian"


def test_detect_ecosystem_rpm_via_package_patterns():
    os_info = "Linux-generic"
    pkgs = [{"package": "kernel", "version": "5.14.0-362.18.1.el9_3"}]
    assert vuln._detect_ecosystem(os_info, pkgs) == "RPM"



def test_build_triplets_skips_packages_without_name_or_version():
    rows = [
        {"package": "openssl", "version": "1.1.1f-1ubuntu2.20"},
        {"package": "", "version": "1.0"},
        {"package": "vim", "version": ""},
        {"package": "wget", "version": "1.21.2-2ubuntu1.1"},
    ]
    triples = vuln._build_triplets(rows, "Debian")
    assert [(t[0], t[1]) for t in triples] == [
        ("openssl", "1.1.1f-1ubuntu2.20"),
        ("wget", "1.21.2-2ubuntu1.1"),
    ]
    assert triples[0][3] != triples[0][1]


def test_build_triplets_non_debian_keeps_raw_version():
    rows = [{"package": "openssl", "version": "1.1.1f"}]
    triples = vuln._build_triplets(rows, "RPM")
    assert triples[0][3] == "1.1.1f"
    assert triples[0][4] == "1.1.1f"



def test_osv_query_batch_returns_empty_when_endpoint_unresolved(monkeypatch):
    """If resolve_osv_endpoint never picked a base (e.g. air-gapped without a
    mirror), batch queries must short-circuit instead of hammering DNS."""
    monkeypatch.setattr(vuln, "_OSV_BASE", "")
    queries = [{"package": {"name": "x", "ecosystem": "Debian"}, "version": "1.0"}]
    out = vuln._osv_query_batch(queries)
    assert out == [{"vulns": []}]


# --------------------------------------------------------------------------
# What the scan cannot do, said out loud
# --------------------------------------------------------------------------

def test_windows_is_skipped_with_a_reason_not_queried_as_nuget():
    """`new_findings=0` every cycle is not a clean result here; it is no
    result.

    A Windows agent's `packages` rows come from walking the registry's
    `Uninstall` keys, so they are display names - "Google Chrome", "Microsoft
    Visual C++ 2015-2022 Redistributable (x64)". This mapped them to OSV's
    `NuGet` ecosystem, which holds .NET library identifiers like
    `Newtonsoft.Json`. The two name spaces do not overlap and OSV has no
    ecosystem for programs installed on Windows, so the query was structurally
    incapable of matching - while the console showed a host with no known
    vulnerabilities.

    A coincidental hit against a real NuGet package would have been worse than
    none, which is the other half of why this is a skip rather than a
    best-effort lookup.
    """
    import inspect

    from scanners import vuln

    source = inspect.getsource(vuln.scan_agent)
    assert "windows_inventory_has_no_osv_ecosystem" in source, \
        "a Windows agent must be reported as unscanned, not as clean"
    assert '"NuGet"' not in source, \
        "Windows display names are being queried as NuGet package names again"


def test_the_skip_reason_reaches_the_console():
    """A reason nobody sees is the same as no reason. `AgentDetail` already
    renders `skipped_reason` beside the scan counts."""
    import pathlib

    page = (pathlib.Path(__file__).resolve().parent.parent
            / "frontend" / "src" / "pages" / "AgentDetail.tsx").read_text(encoding="utf-8")
    assert "skipped_reason" in page
