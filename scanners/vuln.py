"""Server-side vulnerability scanner.

Reads each agent's `packages` table (decrypting Fernet-encrypted values
written by the agent), queries the OSV API, and writes plaintext rows into
the agent's `vulnerabilities_report` table. Moves the OSV scan workload
off the agent so endpoints don't burn CPU on a periodic find_vuln run.

Air-gap support: at boot the module probes the configured public OSV URL.
If the probe fails AND a mirror URL is set, all subsequent queries hit the
mirror instead. Operators can also force a side via OSV_MODE.

Public surface:
- scan_agent(agent, fernet_key, connect_db_for_agent) -> dict
- scan_all_agents(fernet_key, connect_db_for_agent, list_agents) -> list[dict]
- resolve_osv_endpoint() -> str
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json as _json
import os
import re
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests
from cryptography.fernet import Fernet, InvalidToken

OSV_PUBLIC_BASE = os.getenv("OSV_PUBLIC_URL", "https://api.osv.dev").rstrip("/")
OSV_MIRROR_BASE = (os.getenv("OSV_MIRROR_URL") or "").rstrip("/")
OSV_MODE = os.getenv("OSV_MODE", "auto").strip().lower()

HTTP_TIMEOUT = 20
PROBE_TIMEOUT = 4
BATCH_SIZE = 25
ENC_PREFIX = "ENC::"

_OSV_BASE: Optional[str] = None


def _osv_query_url() -> str:
    base = _OSV_BASE or OSV_PUBLIC_BASE
    return f"{base}/v1/query"


def _osv_querybatch_url() -> str:
    base = _OSV_BASE or OSV_PUBLIC_BASE
    return f"{base}/v1/querybatch"


def _probe(base: str) -> bool:
    """Return True if base/v1/query answers — even a 4xx counts (means the
    server is up; the empty body just gets a validation error). Connection
    errors / timeouts are the real signal that the host is unreachable.
    """
    if not base:
        return False
    try:
        r = requests.post(f"{base}/v1/query", json={}, timeout=PROBE_TIMEOUT)
        return r.status_code < 500
    except requests.RequestException:
        return False


def resolve_osv_endpoint() -> str:
    """Pick the OSV base URL to use for the rest of this process lifetime.

    Logic:
      - OSV_MODE=online   → always public (no probe, no fallback)
      - OSV_MODE=mirror   → always mirror (errors out if mirror unset)
      - OSV_MODE=auto     → probe public; if unreachable & mirror set, use mirror
    """
    global _OSV_BASE
    if OSV_MODE == "online":
        _OSV_BASE = OSV_PUBLIC_BASE
        print(f"[vuln_scanner] OSV_MODE=online → using {_OSV_BASE}", flush=True)
        return _OSV_BASE
    if OSV_MODE == "mirror":
        if not OSV_MIRROR_BASE:
            print("[vuln_scanner] OSV_MODE=mirror but OSV_MIRROR_URL is empty — scans will fail", flush=True)
            _OSV_BASE = ""
            return _OSV_BASE
        _OSV_BASE = OSV_MIRROR_BASE
        print(f"[vuln_scanner] OSV_MODE=mirror → using {_OSV_BASE}", flush=True)
        return _OSV_BASE

    if _probe(OSV_PUBLIC_BASE):
        _OSV_BASE = OSV_PUBLIC_BASE
        print(f"[vuln_scanner] OSV reachable, using public API: {_OSV_BASE}", flush=True)
        return _OSV_BASE

    if OSV_MIRROR_BASE and _probe(OSV_MIRROR_BASE):
        _OSV_BASE = OSV_MIRROR_BASE
        print(f"[vuln_scanner] OSV public unreachable — falling back to mirror: {_OSV_BASE}", flush=True)
        return _OSV_BASE

    _OSV_BASE = ""
    print("[vuln_scanner] No reachable OSV endpoint (public unreachable, no mirror configured). Scans will be skipped.", flush=True)
    return _OSV_BASE


def _make_dup_fp(pkg_name: str, pkg_version: str, vuln_id: str) -> str:
    raw = f"{pkg_name}|{pkg_version}|{vuln_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _decrypt_field(val: Any, fernet: Fernet) -> Any:
    """Best-effort decrypt: plaintext returned as-is, `enc::` tokens decrypted.

    The prefix comparison is case-insensitive because this module spelled it
    `ENC::` while the agent writes `enc::`
    (`Sentora/modules/enc_db.ENC_PREFIX`). Nothing ever matched, so every
    value was returned as ciphertext and the scanner asked OSV about a package
    literally named `enc::gAAAAABq...`.

    That returns no vulnerabilities, for every agent, forever - and looks
    exactly like a clean estate. `packages` is encrypted on every agent, so
    this scan has never produced a finding.
    """
    if not isinstance(val, str) or not val.lower().startswith(ENC_PREFIX.lower()):
        return val
    token = val[len(ENC_PREFIX):]
    try:
        pt = fernet.decrypt(token.encode("utf-8"))
        try:
            return _json.loads(pt.decode("utf-8"))
        except Exception:
            return pt.decode("utf-8")
    except InvalidToken:
        # Returned as-is on purpose - the row still happened - but the caller
        # has to notice. A package list that is entirely ciphertext produces
        # zero findings and reads as a clean host.
        return val


def _normalize_debianish_version(ver: str) -> Tuple[str, str]:
    if not ver:
        return ver, ver
    v = ver.split(":", 1)[-1]
    v = re.sub(r'-0?ubuntu\d+(?:\.\d+)?', '', v)
    v = re.sub(r'~ubuntu\d+(?:\.\d+)?', '', v)
    v = v.replace('ubuntu', '')
    v = re.sub(r'--+', '-', v).strip('-')
    upstream = v.split('-', 1)[0]
    return v, upstream


def _detect_ecosystem(os_info: Optional[str], pkgs: Optional[List[dict]] = None) -> Optional[str]:
    """Map an agent's reported OS string to an OSV ecosystem identifier.

    Some agents (notably WSL Ubuntu) report a generic kernel string like
    `Linux-6.6.87-microsoft-standard-WSL2-...` without naming the distro,
    which makes a pure-string match return None. When that happens we peek
    at the installed package list to guess the family:
      - hyphenated lowercase names + version like `1.2.3-1ubuntu1` → Debian
      - dotted versions ending in `.elN`/`.fcN`                  → RPM
      - tiny musl-style names                                    → Alpine
    """
    s = (os_info or "").lower()
    if "windows" in s:
        return "Windows"
    if "ubuntu" in s or "debian" in s:
        return "Debian"
    if any(x in s for x in ("rhel", "red hat", "fedora", "centos", "alma", "rocky", "oracle")):
        return "RPM"
    if "alpine" in s:
        return "Alpine"
    if "arch" in s or "manjaro" in s:
        return "ARCH"

    if "linux" in s and pkgs:
        sample = " ".join(((p.get("version") or "") for p in pkgs[:50]))
        if re.search(r"-\d+ubuntu\d", sample) or "deb" in sample.lower():
            return "Debian"
        if re.search(r"\.(el|fc)\d", sample):
            return "RPM"
        return "Debian"

    return None


def _chunked(seq: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _osv_query_batch(queries: List[dict]) -> List[dict]:
    """OSV batch query with single-call fallback. Sync — call from a thread.
    If no OSV endpoint was resolved (air-gap with no mirror), every query
    short-circuits to an empty result instead of raising."""
    if not _OSV_BASE:
        return [{"vulns": []} for _ in queries]

    batch_url = _osv_querybatch_url()
    single_url = _osv_query_url()
    out: List[dict] = []
    for chunk in _chunked(queries, BATCH_SIZE):
        try:
            r = requests.post(batch_url, json={"queries": chunk}, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            data = r.json() or {}
            res = data.get("results") or []
            if len(res) != len(chunk):
                pad = [{"vulns": []} for _ in range(len(chunk) - len(res))]
                res.extend(pad)
            out.extend(res)
        except requests.RequestException as exc:
            print(f"[vuln_scanner] OSV batch failed (size={len(chunk)}): {exc} — falling back to single", file=sys.stderr)
            for q in chunk:
                try:
                    rr = requests.post(single_url, json=q, timeout=HTTP_TIMEOUT)
                    rr.raise_for_status()
                    out.append(rr.json() or {"vulns": []})
                except Exception as e2:
                    print(f"[vuln_scanner] OSV single failed: {e2}", file=sys.stderr)
                    out.append({"vulns": []})
    return out


def _build_triplets(rows: List[dict], ecosystem: str) -> List[Tuple[str, str, str, str, str]]:
    """(bin_name, installed_ver, query_name, norm_ver, upstream_ver)"""
    triples: List[Tuple[str, str, str, str, str]] = []
    for row in rows:
        bin_name = (row.get("package") or "").strip()
        installed_ver = (row.get("version") or "").strip()
        if not bin_name or not installed_ver:
            continue
        if ecosystem == "Debian":
            norm_ver, upstream = _normalize_debianish_version(installed_ver)
        else:
            norm_ver, upstream = installed_ver, installed_ver
        triples.append((bin_name, installed_ver, bin_name, norm_ver, upstream))
    return triples


def _batch_lookup(triples: List[Tuple[str, str, str, str, str]], ecosystem: str) -> Dict[Tuple[str, str], List[dict]]:
    result: Dict[Tuple[str, str], List[dict]] = {(b, v): [] for (b, v, _, _, _) in triples}

    q1 = [{"package": {"name": qn, "ecosystem": ecosystem}, "version": nv} for (_, _, qn, nv, _) in triples]
    if q1:
        for i, res in enumerate(_osv_query_batch(q1)):
            vulns = res.get("vulns") or []
            if vulns:
                b, v = triples[i][0], triples[i][1]
                result[(b, v)].extend(vulns)

    q2_idx: List[int] = []
    q2: List[dict] = []
    for i, t in enumerate(triples):
        b, v, qn, nv, up = t
        if up and up != nv and not result[(b, v)]:
            q2.append({"package": {"name": qn, "ecosystem": ecosystem}, "version": up})
            q2_idx.append(i)
    if q2:
        for k, res in enumerate(_osv_query_batch(q2)):
            vulns = res.get("vulns") or []
            i = q2_idx[k]
            b, v = triples[i][0], triples[i][1]
            if vulns and not result[(b, v)]:
                result[(b, v)].extend(vulns)

    return result


def _extract_ref_url(vuln: dict) -> str:
    for ref in (vuln.get("references") or []):
        url = (ref.get("url") or "").strip()
        if url:
            return url
    return ""


def _hydrate_vuln_details(vuln_ids: List[str]) -> Dict[str, dict]:
    """OSV's /v1/querybatch returns abbreviated vuln stubs ({id, modified}) —
    summary and references are NOT populated. To fill the UI's Summary column,
    fetch each unique CVE via /v1/vulns/<id> once and cache the result.

    Process-wide cache so repeated scans / multiple agents don't re-hit OSV
    for the same CVE.
    """
    if not _OSV_BASE:
        return {}
    out: Dict[str, dict] = {}
    base = _OSV_BASE
    for vid in vuln_ids:
        if not vid:
            continue
        if vid in _VULN_DETAIL_CACHE:
            out[vid] = _VULN_DETAIL_CACHE[vid]
            continue
        try:
            r = requests.get(f"{base}/v1/vulns/{vid}", timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                detail = r.json() or {}
                summary = (detail.get("summary") or "").strip()
                if not summary:
                    raw = (detail.get("details") or "").strip()
                    summary = raw.split("\n")[0][:300] if raw else ""
                payload = {
                    "summary": summary,
                    "details_url": _extract_ref_url(detail),
                }
                _VULN_DETAIL_CACHE[vid] = payload
                out[vid] = payload
            else:
                _VULN_DETAIL_CACHE[vid] = {"summary": "", "details_url": ""}
        except requests.RequestException as e:
            print(f"[vuln_scanner] hydrate failed for {vid}: {e}", file=sys.stderr)
    return out


_VULN_DETAIL_CACHE: Dict[str, dict] = {}


async def _fetch_decrypted_packages(agent: str, fernet: Fernet, connect_db_for_agent: Callable) -> List[dict]:
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        try:
            await cur.execute("SELECT `package`, `version` FROM packages")
        except Exception as qerr:
            err = str(qerr)
            if "1146" in err or "doesn't exist" in err.lower():
                return []
            raise
        rows = await cur.fetchall()
    finally:
        await cur.close()
        await cnx.close()
    out: List[dict] = []
    for r in rows:
        out.append({
            "package": _decrypt_field(r[0], fernet) if r[0] is not None else "",
            "version": _decrypt_field(r[1], fernet) if r[1] is not None else "",
        })
    return out


async def _fetch_agent_os(agent: str, connect_db_for_agent: Callable) -> Optional[str]:
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        try:
            await cur.execute("SELECT os_info FROM agent_info ORDER BY last_seen DESC LIMIT 1")
            row = await cur.fetchone()
            return row[0] if row and row[0] else None
        except Exception:
            return None
    finally:
        await cur.close()
        await cnx.close()


async def _ensure_vuln_table(agent: str, connect_db_for_agent: Callable) -> None:
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        await cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities_report (
              id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
              package_name     TEXT NULL,
              package_version  TEXT NULL,
              vulnerability_id TEXT NULL,
              summary          TEXT NULL,
              details_url      TEXT NULL,
              dup_fp           CHAR(64) NULL,
              sent             TINYINT(1) NOT NULL DEFAULT 0,
              created_at       TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
              KEY idx_vr_vuln (vulnerability_id(32)),
              KEY idx_vr_pkg  (package_name(191)),
              KEY idx_vr_dup  (dup_fp)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        await cnx.commit()
    finally:
        await cur.close()
        await cnx.close()


async def _existing_dup_fps(agent: str, connect_db_for_agent: Callable) -> set:
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        await cur.execute("SELECT dup_fp FROM vulnerabilities_report WHERE dup_fp IS NOT NULL")
        rows = await cur.fetchall()
    finally:
        await cur.close()
        await cnx.close()
    return {r[0] for r in rows if r and r[0]}


async def _backfill_missing_summaries(agent: str, connect_db_for_agent: Callable) -> int:
    """Fill empty `summary`/`details_url` cells on legacy findings that were
    inserted before /v1/vulns/<id> hydration was added. Pulls each unique
    CVE id whose summary is blank, hydrates via OSV (cached), and UPDATEs.
    Returns rows updated.
    """
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        await cur.execute(
            "SELECT DISTINCT vulnerability_id FROM vulnerabilities_report "
            "WHERE vulnerability_id IS NOT NULL AND vulnerability_id <> '' "
            "AND (summary IS NULL OR summary = '')"
        )
        rows = await cur.fetchall()
    finally:
        await cur.close()
        await cnx.close()
    ids = [r[0] for r in rows if r and r[0]]
    if not ids:
        return 0
    detail_map = await asyncio.to_thread(_hydrate_vuln_details, ids)
    if not detail_map:
        return 0
    updated = 0
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    try:
        for vid, detail in detail_map.items():
            summary = detail.get("summary") or ""
            url = detail.get("details_url") or ""
            if not (summary or url):
                continue
            await cur.execute(
                "UPDATE vulnerabilities_report SET summary=%s, details_url=%s "
                "WHERE vulnerability_id=%s AND (summary IS NULL OR summary='')",
                (summary, url, vid),
            )
            updated += cur.rowcount or 0
        await cnx.commit()
    finally:
        await cur.close()
        await cnx.close()
    return updated


async def _insert_findings(agent: str, findings: List[dict], connect_db_for_agent: Callable) -> int:
    if not findings:
        return 0
    cnx = await connect_db_for_agent(agent)
    cur = await cnx.cursor()
    inserted = 0
    try:
        for f in findings:
            try:
                await cur.execute(
                    """INSERT INTO vulnerabilities_report
                       (package_name, package_version, vulnerability_id, summary, details_url, dup_fp, sent)
                       VALUES (%s, %s, %s, %s, %s, %s, 1)""",
                    (
                        f["package_name"],
                        f["package_version"],
                        f["vulnerability_id"],
                        f.get("summary") or "",
                        f.get("details_url") or "",
                        f["dup_fp"],
                    ),
                )
                inserted += 1
            except Exception as e:
                print(f"[vuln_scanner] insert failed for {f.get('package_name')} {f.get('vulnerability_id')}: {e}", file=sys.stderr)
        await cnx.commit()
    finally:
        await cur.close()
        await cnx.close()
    return inserted



# Tables the agent fills from its own local database. An agent whose postgres
# is unreachable sends none of them, while still appearing online: the IP, MAC
# and hostname on the agent page arrive in the connection header and need no
# database at all.
_TELEMETRY_TABLES = ("packages", "siem_events", "process_events",
                     "network_connections", "resource_usage")


async def _agent_has_no_telemetry(agent: str, connect_db_for_agent) -> bool:
    """True when every telemetry table is empty.

    Distinguishes "this scan found nothing" from "this agent has never sent
    anything", which need different actions and look identical in a console
    showing an empty table.
    """
    try:
        cnx = await connect_db_for_agent(agent)
    except Exception:
        return False                    # cannot tell; do not claim it is empty
    try:
        cur = await cnx.cursor()
        try:
            for table in _TELEMETRY_TABLES:
                try:
                    await cur.execute(f"SELECT 1 FROM `{table}` LIMIT 1")
                    if await cur.fetchone():
                        return False
                except Exception:
                    # A table that does not exist yet is as empty as one that
                    # does, for this question.
                    continue
            return True
        finally:
            await cur.close()
    finally:
        # Closing a connection that is already gone changes nothing, and this
        # runs inside the answer to "why did the scan find nothing" - it must
        # not become the reason there is no answer.
        with contextlib.suppress(Exception):
            await cnx.close()


async def scan_agent(agent: str, fernet_key: str | bytes, connect_db_for_agent: Callable) -> dict:
    """Run an OSV scan for one agent and persist new findings.

    Returns a stat dict: {agent, ecosystem, packages, hits, inserted, skipped_reason?}
    """
    fernet = Fernet(fernet_key.encode("utf-8") if isinstance(fernet_key, str) else fernet_key)

    pkgs = await _fetch_decrypted_packages(agent, fernet, connect_db_for_agent)
    if not pkgs:
        # "no_packages" on its own reads as "this host has no software", which
        # is never true. The usual cause is an agent that connects but has
        # sent no telemetry at all: its own local postgres is unreachable, so
        # every table stays empty while the console still shows the host
        # ONLINE with an IP, a MAC and a hostname - those come from the
        # connection header and need no database.
        #
        # Saying which is easy from here, and saves an operator going through
        # the OSV scanner looking for a fault that is on the endpoint.
        empty = await _agent_has_no_telemetry(agent, connect_db_for_agent)
        reason = ("agent has sent no telemetry at all - its local database is "
                  "probably unreachable; check `docker ps` on the host and "
                  "`journalctl -u sentora-agent`"
                  if empty else
                  "no packages collected yet - the inventory runs on a timer "
                  "after the agent starts")
        return {"agent": agent, "ecosystem": None, "packages": 0, "hits": 0,
                "inserted": 0, "skipped_reason": reason}

    # A package list that is still ciphertext produces zero findings and reads
    # as a clean host, which is the most dangerous way for this scan to fail.
    # It failed exactly that way for a long time: the prefix comparison in
    # _decrypt_field was case-sensitive and did not match what the agent
    # writes, so every name went to OSV as `enc::gAAAAABq...`.
    undecrypted = sum(1 for p in pkgs
                      if str(p.get("package", "")).lower().startswith(ENC_PREFIX.lower()))
    if undecrypted == len(pkgs):
        return {"agent": agent, "ecosystem": None, "packages": len(pkgs),
                "hits": 0, "inserted": 0,
                "skipped_reason": (
                    f"all {len(pkgs)} package names are still encrypted - this "
                    f"server's key does not match the one the agent used. "
                    f"Restart the agent so it re-fetches from "
                    f"/api/agents/bootstrap; rows already stored under the old "
                    f"key stay unreadable.")}

    os_info = await _fetch_agent_os(agent, connect_db_for_agent)
    ecosystem = _detect_ecosystem(os_info, pkgs)
    if not ecosystem or ecosystem == "ARCH":
        return {"agent": agent, "ecosystem": ecosystem, "packages": len(pkgs), "hits": 0, "inserted": 0, "skipped_reason": "unsupported_ecosystem"}

    query_eco = ecosystem if ecosystem != "Windows" else "NuGet"

    triples = _build_triplets(pkgs, ecosystem)
    if not triples:
        return {"agent": agent, "ecosystem": ecosystem, "packages": len(pkgs), "hits": 0, "inserted": 0, "skipped_reason": "no_valid_triplets"}

    binver_to_vulns = await asyncio.to_thread(_batch_lookup, triples, query_eco)

    await _ensure_vuln_table(agent, connect_db_for_agent)
    await _backfill_missing_summaries(agent, connect_db_for_agent)
    existing = await _existing_dup_fps(agent, connect_db_for_agent)

    pending_ids: set = set()
    for (bin_name, installed_ver), vulns in binver_to_vulns.items():
        for v in vulns or []:
            vid = (v.get("id") or "").strip()
            if not vid:
                continue
            fp = _make_dup_fp(bin_name, installed_ver, vid)
            if fp not in existing:
                pending_ids.add(vid)

    detail_map = await asyncio.to_thread(_hydrate_vuln_details, list(pending_ids)) if pending_ids else {}

    findings: List[dict] = []
    total_hits = 0
    for (bin_name, installed_ver), vulns in binver_to_vulns.items():
        if not vulns:
            continue
        total_hits += len(vulns)
        for v in vulns:
            vid = (v.get("id") or "").strip()
            if not vid:
                continue
            fp = _make_dup_fp(bin_name, installed_ver, vid)
            if fp in existing:
                continue
            detail = detail_map.get(vid, {})
            findings.append({
                "package_name": bin_name,
                "package_version": installed_ver,
                "vulnerability_id": vid,
                "summary": detail.get("summary") or (v.get("summary") or "").strip(),
                "details_url": detail.get("details_url") or _extract_ref_url(v),
                "dup_fp": fp,
            })
            existing.add(fp)

    inserted = await _insert_findings(agent, findings, connect_db_for_agent)
    return {
        "agent": agent,
        "ecosystem": ecosystem,
        "packages": len(pkgs),
        "hits": total_hits,
        "inserted": inserted,
    }


async def scan_all_agents(fernet_key: str | bytes,
                          connect_db_for_agent: Callable,
                          list_agents: Callable) -> List[dict]:
    """Scan every known agent. `list_agents` is a sync or async callable
    returning a list of agent name strings.
    """
    res = list_agents()
    if asyncio.iscoroutine(res):
        agents = await res
    else:
        agents = res
    out: List[dict] = []
    for a in agents or []:
        try:
            stat = await scan_agent(a, fernet_key, connect_db_for_agent)
        except Exception as e:
            stat = {"agent": a, "error": str(e)}
            print(f"[vuln_scanner] scan failed for {a}: {e}", file=sys.stderr)
        out.append(stat)
    return out
