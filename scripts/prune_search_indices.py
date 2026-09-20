"""Remove the search indices Sentora no longer writes.

`core/opensearch.INDEXED_TABLES` is an allowlist now. Before it existed, every
ingested table was indexed, which produced two piles nobody asked for:

    sentora-logs-hardware-inventory   426,768 documents
    sentora-logs-packages             255,534
    sentora-logs-software-inventory   165,297
    sentora-logs-network-connections  165,068
    sentora-logs-docker-containers     63,364
    sentora-logs-network-inventory     38,142
    sentora-logs-resource-usage        26,181
    sentora-logs-disk-usage             2,630

Those are snapshot and inventory tables. MySQL empties and rewrites them on
every batch; the index kept every copy and none of the deletes, so what looks
like history is a pile of stale rows with no way to tell which one is current.
Each has a route and a view that answers the question exactly.

**Not run automatically, and not from the server.** Deleting an index is not
reversible and these may be the backing store for saved visualisations in
OpenSearch Dashboards - which this script cannot see and must not assume
about. So it prints, asks, and only then deletes.

    docker compose exec sentora-server python scripts/prune_search_indices.py
    docker compose exec sentora-server python scripts/prune_search_indices.py --yes

Nothing here touches MySQL. The rows are still there, and the views still read
them; this removes only the duplicate search copy.
"""
from __future__ import annotations

import argparse
import sys

sys.path.insert(0, ".")

from core import opensearch as os_utils          # noqa: E402


def index_for(table: str) -> str:
    return f"sentora-logs-{table.replace('_', '-')}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes", action="store_true",
                        help="delete without asking")
    args = parser.parse_args()

    client = os_utils.client
    candidates = []

    for table, reason in sorted(os_utils.NOT_INDEXED.items()):
        index = index_for(table)
        try:
            if not client.indices.exists(index=index):
                continue
            count = client.count(index=index).get("count", 0)
        except Exception as exc:
            print(f"[!] {index}: could not be read ({exc}); skipping")
            continue
        candidates.append((index, count, reason))

    if not candidates:
        print("Nothing to prune: no index exists for a table that is no "
              "longer written.")
        return 0

    total = sum(count for _, count, _ in candidates)
    print(f"{len(candidates)} index/indices, {total:,} documents:\n")
    for index, count, reason in candidates:
        print(f"  {index:<40} {count:>10,}  {reason}")

    print("\nThe rows stay in MySQL. This removes the search copy only.")

    if not args.yes:
        # input(), deliberately. A destructive default is how a maintenance
        # script becomes the thing that lost the data.
        answer = input("\nDelete these indices? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Nothing deleted.")
            return 1

    failed = 0
    for index, count, _ in candidates:
        try:
            client.indices.delete(index=index)
            print(f"[+] deleted {index} ({count:,} documents)")
        except Exception as exc:
            failed += 1
            print(f"[!] {index}: {exc}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
