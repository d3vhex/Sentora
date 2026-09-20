import os
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection

from core import telemetry_crypto

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")

client = OpenSearch(
    hosts=[OPENSEARCH_URL],
    http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
    use_ssl=False,
    verify_certs=False,
    connection_class=RequestsHttpConnection
)

#: Tables whose rows are indexed for search, and the reason the rest are not.
#:
#: Every table used to be indexed, which was never a decision - `index_log` was
#: called unconditionally for whatever ingest had just stored. Two costs came
#: out of that:
#:
#:   - **the index held ciphertext.** `siem_events.message` went in as
#:     `enc::gAAAA...`, so `message:powershell` matched 0 of 69 documents while
#:     `source:PowerShell` matched 52 of the same 69. Nine indices and roughly
#:     863,000 documents were unsearchable on the only field that mattered.
#:   - **it grew without bound.** A snapshot table is emptied and rewritten in
#:     MySQL on every batch; the index kept every copy. 426,768
#:     `hardware_inventory` documents for a CPU, some RAM and four disks.
#:
#: The rule is what the search is *for*. An index answers "find this, anywhere
#: in the fleet, in this window" - which suits an append-only event log and
#: does not suit a table whose answer is "the current list for this host".
#: State tables have a route and a view each, and a view gives an exact answer
#: where a time-windowed full-text search gives a vague one.
INDEXED_TABLES = frozenset({
    "siem_events", "events_alert",        # the log, and what the rules said
    "process_events", "registry_logs",    # EDR observations
    "fim_data", "critical_files",         # file and permission changes
    "security_audit",                     # posture findings, hunted fleet-wide
    "soar_actions",                       # what was done in response
    "portscan_result",                    # small, and "who has 3389 open" is
                                          # exactly an index question
    "audit_logs",                         # platform, not agent: who did what
})

#: Deliberately not indexed, with the view that answers the question instead.
#: Kept beside the allowlist so the reason arrives with the name, and asserted
#: against `server.ALLOWED_TABLES` by `tests/test_opensearch_indexing.py` - a
#: table added to ingest and to neither of these is a silent decision.
NOT_INDEXED = {
    "hardware_inventory": "Assets > Hardware. 426,768 documents for one host's components.",
    "software_inventory": "Assets > Software.",
    "network_inventory": "Assets > Ports.",
    "network_connections": "Assets > Network. A snapshot, rewritten every batch.",
    "packages": "Input to the vulnerability scanner; surfaced as vulnerabilities_report.",
    "docker_containers": "Its own view, and a snapshot.",
    "disk_usage": "Dashboard metrics, not events.",
    "resource_usage": "Dashboard metrics, not events.",
    "vulnerabilities_report": "Written server-side by scanners/vuln.py, which never called this.",
}


async def index_log(agent: str, table: str, item: dict):
    """Index one row for search, decrypted, if this table is searched at all.

    **Decrypted here and nowhere upstream.** `core/telemetry_crypto` lists
    where agent telemetry is turned back into plaintext - the prompt and the
    correlation fields - and where it is not: the stored row and the broker
    message. The index was a fifth destination that list never mentioned, and
    it got ciphertext by default rather than by choice.

    Indexing plaintext is a real cost, not a free fix: `sentora-logs-*` becomes
    a readable copy of the telemetry it covers, so it has to be treated as
    sensitive - see `docs/production-deployment.md`. The alternative was a hunt
    surface that cannot match a process name, which is not a security control,
    only a broken feature that reports success.

    A value that will not decrypt is indexed as it stands. `decrypt_value`
    counts those, and a missing key is reported rather than guessed at: an
    index quietly holding ciphertext is what this change exists to end.
    """
    if table not in INDEXED_TABLES:
        return None

    try:
        index_name = f"sentora-logs-{table.replace('_', '-')}"

        doc = telemetry_crypto.decrypt_item(table, dict(item))
        doc["agent_name"] = agent
        doc["@timestamp"] = datetime.now().isoformat()

        doc.pop("id", None)

        response = client.index(
            index=index_name,
            body=doc,
            refresh=True
        )
        return response
    except Exception as e:
        print(f"[OpenSearch] Error indexing log: {e}")
        return None

class SearchError(Exception):
    """A search that could not run, with the reason the engine gave.

    Separate from "found nothing" on purpose. This used to catch everything
    and return None, which the endpoint turned into `{"hits": []}` - so a
    malformed query, an unreachable OpenSearch and a genuinely empty result
    were the same screen. On a security console the difference between "no
    matches" and "the search did not run" is the difference between an
    all-clear and no answer at all.
    """


def search_logs(query_body: dict, index_mask: str = "sentora-logs-*"):
    """Run a query. Raises SearchError if it could not run."""
    try:
        return client.search(index=index_mask, body=query_body)
    except Exception as e:
        # The engine's own message is what tells an operator that they wrote
        # `severtiy:high` - a summary of it does not.
        detail = getattr(e, "info", None) or {}
        reason = ""
        if isinstance(detail, dict):
            root = (detail.get("error") or {}).get("root_cause") or []
            if root:
                reason = root[0].get("reason") or ""
        raise SearchError(reason or str(e)) from e


def log_fields(index_mask: str = "sentora-logs-*") -> list:
    """Field names present in the log indices, for the filter builder.

    Read from the mapping rather than kept as a list: the indices are created
    by dynamic mapping from whatever the agents send, so any hand-maintained
    list would describe a schema nobody wrote.
    """
    try:
        mapping = client.indices.get_mapping(index=index_mask)
    except Exception as e:
        print(f"[OpenSearch] mapping unavailable: {e}", flush=True)
        return []

    names: set[str] = set()

    def walk(properties: dict, prefix: str = "") -> None:
        for name, spec in (properties or {}).items():
            path = f"{prefix}{name}"
            if "properties" in spec:
                walk(spec["properties"], f"{path}.")
            else:
                names.add(path)

    for index in mapping.values():
        walk(((index.get("mappings") or {}).get("properties")) or {})
    return sorted(names)
