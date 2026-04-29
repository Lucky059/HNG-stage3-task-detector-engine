"""
unbanner.py — automatic unban with exponential-backoff schedule.

Backoff schedule (from config):  [10, 30, 120] minutes.

Each banned IP gets a BanRecord that tracks:
  • when it was banned
  • how many times it has been banned (strike count)
  • what the next unban time is

On unban:
  • If strike < len(schedule): schedule next unban after schedule[strike] minutes
  • If strike >= len(schedule): permanent ban (never unban)

A background thread wakes up every 30 seconds and checks whether any ban
has expired.
"""

import threading, time
from dataclasses import dataclass, field
from typing import Optional
from blocker import unblock_ip
from notifier import send_slack, audit_log
import config


@dataclass
class BanRecord:
    ip:           str
    banned_at:    float
    strike:       int = 0
    unban_at:     Optional[float] = None
    permanent:    bool = False


class Unbanner:
    def __init__(self, detector_banned_set: set):
        """
        detector_banned_set — reference to Detector.banned so we can
        remove IPs from it when they are unbanned.
        """
        cfg = config.get()
        self._schedule    = [m * 60 for m in cfg["unban_schedule"]]  # → seconds
        self._records:    dict[str, BanRecord] = {}
        self._banned_set  = detector_banned_set
        self._lock        = threading.Lock()

    def register_ban(self, ip: str):
        """Called immediately after an IP is banned."""
        with self._lock:
            rec = self._records.get(ip)
            if rec is None:
                rec = BanRecord(ip=ip, banned_at=time.time())
                self._records[ip] = rec
            else:
                rec.banned_at = time.time()
                rec.strike   += 1

            if rec.strike >= len(self._schedule):
                rec.permanent = True
                rec.unban_at  = None
                print(f"[unbanner] {ip} → PERMANENT BAN (strike {rec.strike})")
            else:
                delay        = self._schedule[rec.strike]
                rec.unban_at = time.time() + delay
                print(f"[unbanner] {ip} → unban in {delay//60}m (strike {rec.strike})")

    def run(self):
        """Background loop — call in a daemon thread."""
        while True:
            self._tick()
            time.sleep(30)

    def _tick(self):
        now = time.time()
        with self._lock:
            for ip, rec in list(self._records.items()):
                if rec.permanent:
                    continue
                if rec.unban_at and now >= rec.unban_at:
                    self._do_unban(ip, rec)

    def _do_unban(self, ip: str, rec: BanRecord):
        unblock_ip(ip)
        self._banned_set.discard(ip)

        # Schedule next ban duration (for when re-banned)
        rec.strike += 1
        rec.unban_at = None

        dur_label = "permanent-next" if rec.strike >= len(self._schedule) else \
                    f"{self._schedule[rec.strike]//60}m-next"

        send_slack(
            event="UNBAN",
            ip=ip,
            condition=f"backoff strike={rec.strike}",
            rate=0,
            baseline=0,
            duration=dur_label,
        )
        audit_log("UNBAN", ip, f"backoff strike={rec.strike}", 0, 0, dur_label)
