import os
import sys
import json
import hashlib
import platform
import shutil
import subprocess
import requests
import re
from typing import List, Dict, Tuple, Optional

import modules.enc_db as enc_db
enc_db.add_encrypted_fields(
    "vulnerabilities_report",
    ["package_name", "package_version", "vulnerability_id", "summary", "details_url"]
)

insert_record_enc   = enc_db.insert_record_enc
fetch_recent_dec    = enc_db.fetch_recent_dec
fetch_where_dec     = enc_db.fetch_where_dec

OSV_QUERY_URL       = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL  = "https://api.osv.dev/v1/querybatch"
TABLE               = "vulnerabilities_report"
BATCH_SIZE          = 25
HTTP_TIMEOUT        = 20

def make_dup_fp(pkg_name: str, pkg_version: str, vuln_id: str) -> str:
    raw = f"{pkg_name}|{pkg_version}|{vuln_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def is_duplicate(pkg_name: str, pkg_version: str, vuln_id: str) -> bool:
    dup_fp = make_dup_fp(pkg_name, pkg_version, vuln_id)
    rows = fetch_where_dec(TABLE, where="dup_fp = %s", params=(dup_fp,), limit=1)
    return bool(rows)

def normalize_debianish_version(ver: str) -> Tuple[str, str]:
    """
    Ubuntu/Debian türevi sürümleri OSV-Debian ile uyumlu hale getir.
    Dönen: (normalized, upstream_only)
    """
    if not ver:
        return ver, ver
    v = ver.split(":", 1)[-1]
    v = re.sub(r'-0?ubuntu\d+(?:\.\d+)?', '', v)
    v = re.sub(r'~ubuntu\d+(?:\.\d+)?', '', v)
    v = v.replace('ubuntu', '')
    v = re.sub(r'--+', '-', v).strip('-')
    upstream = v.split('-', 1)[0]
    return v, upstream

def detect_osv_ecosystem() -> Optional[str]:
    system = platform.system().lower()
    if system == "windows":
        return "Windows"
    if system != "linux":
        return None
    try:
        data = open("/etc/os-release", encoding="utf-8").read().lower()
    except FileNotFoundError:
        return None
    if "arch" in data or "manjaro" in data:
        return "ARCH"
    if "debian" in data or "ubuntu" in data:
        return "Debian"
    if any(x in data for x in ["rhel", "red hat", "fedora", "centos", "alma", "rocky", "oracle linux", "ol"]):
        return "RPM"
    if "alpine" in data:
        return "Alpine"
    return None

def osv_check_single(package_name: str, package_version: str, ecosystem: str) -> dict:
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}, "version": package_version}
    try:
        r = requests.post(OSV_QUERY_URL, json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json() or {}
    except requests.RequestException as exc:
        print(f"[OSV] {ecosystem} lookup failed for {package_name} {package_version}: {exc}", file=sys.stderr)
        return {}

def _chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

def osv_query_batch(queries: List[dict]) -> List[dict]:
    """
    queries: [{"package":{"name":..., "ecosystem":...}, "version":"..."}]
    return:  [{"vulns":[...]} ...] (giriş sırasına hizalı)
    """
    results: List[dict] = []
    for chunk in _chunked(queries, BATCH_SIZE):
        try:
            r = requests.post(OSV_QUERYBATCH_URL, json={"queries": chunk}, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            data = r.json() or {}
            res = data.get("results") or []
            if len(res) != len(chunk):
                pad = [{"vulns": []} for _ in range(len(chunk) - len(res))]
                res.extend(pad)
            results.extend(res)
        except requests.RequestException as exc:
            print(f"[OSV] batch failed (size={len(chunk)}): {exc} → falling back to single requests", file=sys.stderr)
            for q in chunk:
                results.append(osv_check_single(q["package"]["name"], q["version"], q["package"]["ecosystem"]))
    return results

def build_dpkg_source_map() -> Dict[str, Tuple[str, str]]:
    """
    binary -> (source_or_binary, version)
    ${source:Package} boş ise binary ile aynı olur.
    """
    fmt = "${Package}\t${source:Package}\t${Version}\n"
    try:
        cp = subprocess.run(
            ["dpkg-query", "-W", f"-f={fmt}"],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace',
        )
        mapping: Dict[str, Tuple[str, str]] = {}
        for line in cp.stdout.splitlines():
            if not line.strip():
                continue
            pkg, src, ver = (x.strip() for x in line.split("\t"))
            src = src or pkg
            mapping[pkg.lower()] = (src, ver)
        return mapping
    except Exception as e:
        print(f"[dpkg-query] failed: {e}", file=sys.stderr)
        return {}

def to_query_triplets(pkg_rows: List[dict], ecosystem: str, src_map: Dict[str, Tuple[str, str]]) -> List[Tuple[str, str, str, str, str]]:
    """
    Her paket için üçlüler oluştur:
    (bin_name, installed_ver, query_name, norm_ver, upstream_ver)
    """
    triples = []
    for row in pkg_rows:
        bin_name = (row.get("package") or "").strip()
        installed_ver = (row.get("version") or "").strip()
        if not bin_name:
            continue
        if ecosystem == "Debian":
            query_name = (src_map.get(bin_name.lower(), (bin_name, installed_ver))[0] or bin_name).strip()
            norm_ver, upstream_ver = normalize_debianish_version(installed_ver)
        else:
            query_name, norm_ver, upstream_ver = bin_name, installed_ver, installed_ver
        triples.append((bin_name, installed_ver, query_name, norm_ver, upstream_ver))
    return triples

def batch_lookup_with_fallback(triples: List[Tuple[str, str, str, str, str]], ecosystem: str) -> Dict[Tuple[str, str], List[dict]]:
    """
    3 aşamalı toplu tarama:
      1) source+normalized
      2) source+upstream-only (norm != upstream ise)
      3) binary+normalized (source=binary olasılığı)
    Dönen: {(bin_name, installed_ver): [vuln_dict, ...]}
    """
    result_map: Dict[Tuple[str, str], List[dict]] = { (b,v): [] for (b,v,_,_,_) in triples }

    q1 = [{"package": {"name": qn, "ecosystem": ecosystem}, "version": nv} for (_,_,qn,nv,_) in triples]
    r1 = osv_query_batch(q1)
    for i, res in enumerate(r1):
        vulns = res.get("vulns") or []
        b, v = triples[i][0], triples[i][1]
        if vulns:
            result_map[(b, v)].extend(vulns)

    pending_idxs = [i for i, t in enumerate(triples) if not result_map[(t[0], t[1])]]

    q2, idx2 = [], []
    for i in pending_idxs:
        b, v, qn, nv, up = triples[i]
        if up and up != nv:
            q2.append({"package": {"name": qn, "ecosystem": ecosystem}, "version": up})
            idx2.append(i)
    if q2:
        r2 = osv_query_batch(q2)
        for k, res in enumerate(r2):
            vulns = res.get("vulns") or []
            i = idx2[k]
            b, v = triples[i][0], triples[i][1]
            if vulns and not result_map[(b, v)]:
                result_map[(b, v)].extend(vulns)

    pending_idxs = [i for i, t in enumerate(triples) if not result_map[(t[0], t[1])]]
    q3, idx3 = [], []
    for i in pending_idxs:
        b, v, qn, nv, up = triples[i]
        if qn != b:
            q3.append({"package": {"name": b, "ecosystem": ecosystem}, "version": nv})
            idx3.append(i)
    if q3:
        r3 = osv_query_batch(q3)
        for k, res in enumerate(r3):
            vulns = res.get("vulns") or []
            i = idx3[k]
            b, v = triples[i][0], triples[i][1]
            if vulns and not result_map[(b, v)]:
                result_map[(b, v)].extend(vulns)

    return result_map

def extract_ref_url(vuln: dict) -> str:
    for ref in (vuln.get("references") or []):
        url = (ref.get("url") or "").strip()
        if url:
            return url
    return ""

def main():
    ecosystem = detect_osv_ecosystem()
    print(f"[find_vuln] ecosystem={ecosystem}")

    pkg_rows = fetch_where_dec("packages", where="TRUE", params=(), limit=10000)

    pkg_count = len(pkg_rows or [])
    print(f"[find_vuln] packages_in_db={pkg_count}")
    if not pkg_rows:
        print("[find_vuln] no packages → skipping vuln scan")
        return

    if ecosystem == "ARCH":
        print("[find_vuln] No dedicated path for ARCH ecosystem (skip).", file=sys.stderr)
        return

    if ecosystem == "Windows":
        print("[find_vuln] Windows platform detected. Running limited scan...", file=sys.stderr)
    elif ecosystem not in ("Debian", "RPM", "Alpine"):
        print("[OSV] Unsupported or undetected ecosystem; only Debian/RPM/Alpine/Windows are processed.", file=sys.stderr)
        return

    src_map = build_dpkg_source_map() if ecosystem == "Debian" else {}
    triples = to_query_triplets(pkg_rows, ecosystem or "NuGet", src_map)

    query_ecosystem = ecosystem if ecosystem != "Windows" else "NuGet"
    binver_to_vulns = batch_lookup_with_fallback(triples, query_ecosystem)

    inserted = 0
    total_hits = 0
    for (bin_name, installed_ver), vulns in binver_to_vulns.items():
        if not vulns:
            continue
        total_hits += len(vulns)
        for v in vulns:
            vid = (v.get("id") or "").strip()
            if not vid:
                continue
            if is_duplicate(bin_name, installed_ver, vid):
                continue
            summary = (v.get("summary") or "").strip()
            details_url = extract_ref_url(v)
            payload = {
                "package_name": bin_name,
                "package_version": installed_ver,
                "vulnerability_id": vid,
                "summary": summary,
                "details_url": details_url,
                "dup_fp": make_dup_fp(bin_name, installed_ver, vid),
            }
            try:
                insert_record_enc(TABLE, payload)
                inserted += 1
            except Exception as e:
                print(f"[find_vuln] insert failed for {bin_name} {installed_ver} {vid}: {e}", file=sys.stderr)

    print(f"[find_vuln] matches={total_hits} inserted={inserted}")

