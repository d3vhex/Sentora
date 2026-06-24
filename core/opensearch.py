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

def search_logs(query_body: dict, index_mask: str = "sentora-logs-*"):
    """
    Search logs in OpenSearch.
    """
    try:
        response = client.search(
            index=index_mask,
            body=query_body
        )
        return response
    except Exception as e:
        print(f"[OpenSearch] Search error: {e}")
        return None
