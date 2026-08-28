"""
Shared log-reading logic for the dashboard. Both requests.log and
honeypot.log are JSON-lines files written by other processes (the
proxy and the honeypot) that may still be actively appending to them
while the dashboard reads — this module is written defensively around
that: a line being read mid-write, or a file not existing yet because
its process hasn't started, must never crash a dashboard page.
"""

import json
from pathlib import Path


def read_log(path, ip_filter=None, since=None):
    """
    Read a JSON-lines log file into a list of dicts, oldest first.

    Args:
        path: path to the log file (str or Path)
        ip_filter: if given, only entries whose "ip" field equals this
            string are returned (string)
        since: if given, only entries whose "timestamp" field sorts >=
            this value are returned (string, ISO-8601 — timestamps are
            written with a fixed-width, zero-padded ISO format by both
            loggers, so plain string comparison sorts correctly without
            needing to parse them into datetime objects)

    Returns:
        list of dicts, in file order (oldest first). Missing file ->
        empty list, not an error. Malformed lines (partial write mid-
        append, corrupted line) are skipped rather than raising.
    """
    path = Path(path)
    entries = []

    if not path.exists():
        return entries

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        # File disappeared or became unreadable between the exists()
        # check and the open() — treat like "nothing to show" rather
        # than crashing the dashboard page.
        return entries

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            # A writer process was mid-append when we read, or a line
            # got corrupted. Skip it, don't blow up the whole page over
            # one bad line.
            continue

        if not isinstance(entry, dict):
            continue

        if ip_filter is not None and entry.get("ip") != ip_filter:
            continue

        if since is not None and str(entry.get("timestamp", "")) < since:
            continue

        entries.append(entry)

    return entries
