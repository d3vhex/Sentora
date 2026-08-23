"""Translate compose service names for tooling that runs on the host.

`.env` is written for the containers: `DB_HOST=db`, `OLLAMA_BASE_URL=
http://ollama:11434/api`. Those names resolve on the compose network and
nowhere else. Every host-side script that loads `.env` therefore inherits an
address it cannot reach, and the resulting error names DNS rather than the
actual problem:

    Unknown MySQL server host 'db'
    Failed to resolve 'ollama' ([Errno 11001] getaddrinfo failed)

Both read as "the service is down". Neither is.

This has now bitten three scripts, so the rule lives in one place: when we are
not inside a container and the host is a known compose service, use the
address the service is published on instead.

Only the services `docker-compose.yaml` publishes to the host are listed. A
service with no `ports:` entry is genuinely unreachable from here, and
silently rewriting it to localhost would swap a clear DNS error for a
confusing connection-refused.
"""

from __future__ import annotations

import pathlib
from urllib.parse import urlsplit, urlunsplit

# service name -> (host, published port) from docker-compose.yaml `ports:`
PUBLISHED = {
    "db": ("127.0.0.1", 3307),
    "ollama": ("127.0.0.1", 11434),
    "rabbitmq": ("127.0.0.1", 5672),
}


def in_container() -> bool:
    return pathlib.Path("/.dockerenv").exists()


def resolve_host(host: str, port: int | None = None) -> tuple[str, int | None]:
    """Map a compose service name to its published address when on the host."""
    if in_container() or host not in PUBLISHED:
        return host, port
    pub_host, pub_port = PUBLISHED[host]
    return pub_host, pub_port


def resolve_url(url: str) -> str:
    """Same, for a URL. Returns it unchanged if there is nothing to rewrite."""
    if not url or in_container():
        return url
    parts = urlsplit(url)
    if not parts.hostname or parts.hostname not in PUBLISHED:
        return url
    host, port = PUBLISHED[parts.hostname]
    netloc = f"{host}:{port}"
    if parts.username:
        cred = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{cred}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
