"""
monitor.py — tail the nginx JSON access log and yield parsed entries.

Each yielded entry is a plain dict:
    {
        "source_ip":     str,
        "timestamp":     float,   # Unix epoch
        "method":        str,
        "path":          str,
        "status":        int,
        "response_size": int,
    }

HOW IT WORKS
────────────
We open the log file and seek to the end (we only care about NEW lines).
We then loop forever:
  • Try to read a line.
  • If the file has been rotated (inode changed), reopen it.
  • If no new line yet, sleep briefly and retry — this is the "tail -F" behaviour.
"""

import json, os, time, stat
from datetime import datetime, timezone
import config


def _inode(path: str) -> int:
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return -1


def _parse_line(raw: str) -> dict | None:
    """Parse one JSON log line.  Returns None if the line is malformed."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        d = json.loads(raw)
        # Convert ISO-8601 timestamp → Unix float
        ts_str = d.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            ts = time.time()

        return {
            "source_ip":     d.get("source_ip", "0.0.0.0"),
            "timestamp":     ts,
            "method":        d.get("method", ""),
            "path":          d.get("path", ""),
            "status":        int(d.get("status", 0)),
            "response_size": int(d.get("response_size", 0)),
        }
    except Exception:
        return None


def tail_log():
    """
    Generator — yields parsed log entries forever.

    Blocks briefly (0.1 s) when there are no new lines so we don't
    burn CPU in a busy-wait loop.
    """
    cfg  = config.get()
    path = cfg["log_path"]

    # Wait for the file to appear (might start before nginx writes anything)
    while not os.path.exists(path):
        print(f"[monitor] waiting for {path} …")
        time.sleep(1)

    fh      = open(path, "r", errors="replace")
    fh.seek(0, 2)          # jump to END so we only see NEW lines
    current_inode = _inode(path)

    while True:
        line = fh.readline()

        if line:
            entry = _parse_line(line)
            if entry:
                yield entry
        else:
            # Check for log rotation (nginx logrotate or copytruncate)
            new_inode = _inode(path)
            if new_inode != current_inode and new_inode != -1:
                print("[monitor] log rotated — reopening")
                fh.close()
                fh = open(path, "r", errors="replace")
                current_inode = new_inode
            else:
                time.sleep(0.05)   # small sleep when idle

