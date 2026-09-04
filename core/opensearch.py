import os
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection

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

async def index_log(agent: str, table: str, item: dict):
    """
    Index a single log entry into OpenSearch.
    Index name pattern: sentora-logs-<table_name>
    """
    try:
        index_name = f"sentora-logs-{table.replace('_', '-')}"
        
        doc = dict(item)
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
