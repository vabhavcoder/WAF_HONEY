"""JSON-lines request logging used by the proxy and future detectors."""
import datetime
import json
from pathlib import Path
from typing import Any, Mapping

from proxy.config import LOG_PATH


def log_request(
    ip: str,
    method: str,
    path: str,
    status: int,
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Append one structured request record to the configured JSONL log."""
    entry: dict[str, Any] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
    }
    if extra:
        entry["extra"] = dict(extra)

    log_file = Path(LOG_PATH)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
