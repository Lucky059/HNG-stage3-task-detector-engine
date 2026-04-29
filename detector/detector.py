"""
detector.py — sliding-window anomaly detection engine.

SLIDING WINDOW (deque)
──────────────────────
Two deques are maintained:
  • per-IP deque  : stores timestamps of requests from one IP
  • global deque  : stores ALL request timestamps

Each deque entry is just a float timestamp (seconds).
On every new request we:
  1. Append the new timestamp.
  2. Pop from the LEFT (popleft) while the oldest entry is outside the
     60-second window.  This is O(1) — the deque is always sorted because
     we only ever append to the right.

The current rate = len(deque) / window_seconds.

ANOMALY DECISION
────────────────
Given rate R, mean μ, stddev σ:

  z-score  = (R − μ) / max(σ, 0.001)    ← avoid division by zero

An anomaly fires if EITHER:
  • z-score  ≥ zscore_threshold   (default 3.0)
  • R        ≥ mean * rate_multiplier  (default 5×)

ERROR SURGE (tightened thresholds)
───────────────────────────────────
If an IP's 4xx/5xx rate is ≥ 3× the baseline error rate, we halve both
thresholds for that IP so it gets flagged more quickly.
"""

import time, threading
from collections import deque, defaultdict
from typing import Optional
import config
from baseline import Baseline
from blocker import block_ip
from notifier import send_slack, audit_log


class Detector:
    def __init__(self):
        cfg = config.get()
        self.window      = cfg["window_seconds"]           # 60 s
        self.z_thresh    = cfg["zscore_threshold"]         # 3.0
        self.rate_mult   = cfg["rate_multiplier"]          # 5×
        self.err_mult    = cfg["error_rate_multiplier"]    # 3×

        self.global_baseline = Baseline("global")
        self.error_baseline  = Baseline("errors")

        # per-IP sliding windows  {ip: deque([ts, ...])}
        self._ip_windows: dict[str, deque] = defaultdict(deque)

        # per-IP error windows
        self._ip_err_windows: dict[str, deque] = defaultdict(deque)

        # global window
        self._global_window: deque = deque()

        # stats for dashboard
        self.global_rps    = 0.0
        self.top_ips: dict[str, int]  = {}
        self._lock         = threading.Lock()

        # set of currently banned IPs (managed by blocker/unbanner)
        self.banned: set[str] = set()

    # ── Entry point ───────────────────────────────────────────────────────

    def process(self, entry: dict):
        """Called for every parsed log line."""
        now = time.time()
        ip  = entry["source_ip"]
        is_error = entry["status"] >= 400

        with self._lock:
            self._push(self._global_window, now)
            self._push(self._ip_windows[ip], now)
            if is_error:
                self._push(self._ip_err_windows[ip], now)

            global_rate = len(self._global_window) / self.window
            ip_rate     = len(self._ip_windows[ip]) / self.window
            err_rate    = len(self._ip_err_windows[ip]) / self.window

            self.global_rps = global_rate

            # Update per-second baselines once per second
            # (We approximate: if enough time has passed since last update)
            self.global_baseline.update(now, global_rate)
            self.error_baseline.update(now, err_rate)

            # ── Check per-IP anomaly ──────────────────────────────────────
            if ip not in self.banned:
                self._check_ip(ip, ip_rate, err_rate, now)

            # ── Check global anomaly ──────────────────────────────────────
            self._check_global(global_rate, now)

            # Build top-10 snapshot
            self.top_ips = {
                k: len(v)
                for k, v in sorted(
                    self._ip_windows.items(),
                    key=lambda x: len(x[1]),
                    reverse=True,
                )[:10]
            }

    # ── Private ───────────────────────────────────────────────────────────

    def _push(self, dq: deque, now: float):
        """Append timestamp and evict expired entries from left."""
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _check_ip(self, ip: str, ip_rate: float, err_rate: float, now: float):
        mean, stddev, n = self.global_baseline.get_stats()
        if n < 5:
            return   # not enough data yet

        err_mean, _, _ = self.error_baseline.get_stats()

        # Tighten thresholds when error surge detected
        z_thresh   = self.z_thresh
        rate_mult  = self.rate_mult
        if err_mean > 0 and err_rate >= err_mean * self.err_mult:
            z_thresh  /= 2
            rate_mult /= 2

        z = (ip_rate - mean) / max(stddev, 0.001)

        if z >= z_thresh or ip_rate >= mean * rate_mult:
            condition = f"z={z:.2f}" if z >= z_thresh else f"rate={ip_rate:.1f}rps>={mean*rate_mult:.1f}"
            self.banned.add(ip)
            block_ip(ip)
            dur = "10m"
            send_slack(
                event="BAN",
                ip=ip,
                condition=condition,
                rate=ip_rate,
                baseline=mean,
                duration=dur,
            )
            audit_log("BAN", ip, condition, ip_rate, mean, dur)

    def _check_global(self, rate: float, now: float):
        mean, stddev, n = self.global_baseline.get_stats()
        if n < 5:
            return

        z = (rate - mean) / max(stddev, 0.001)
        if z >= self.z_thresh or rate >= mean * self.rate_mult:
            condition = f"GLOBAL z={z:.2f} rate={rate:.1f}"
            send_slack(
                event="GLOBAL_ANOMALY",
                ip="N/A",
                condition=condition,
                rate=rate,
                baseline=mean,
                duration="no-block",
            )
