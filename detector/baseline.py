"""
baseline.py — rolling baseline for request rate.

CONCEPT
───────
We keep a deque of (second_bucket, count) pairs covering the last 30 minutes.
Every 60 seconds we recalculate mean and stddev from those samples.

Per-hour slots: we also maintain a dict  {hour_of_day: [sample, …]}
so that if the current hour has ≥ baseline_min_samples data points, we
prefer those over the full 30-minute window.  This lets the engine adapt
to natural traffic patterns (e.g. night vs day).

Floor values prevent division-by-zero and stop the baseline collapsing to
near-zero during quiet periods (which would trigger false positives on
normal bursts).

Public API
──────────
  update(ts, count)   → call once per second with the current RPS
  get_stats()         → returns (mean, stddev, sample_count)
  get_error_stats()   → same but for error-rate baseline
"""

import math, time, threading
from collections import deque
from typing import Tuple
import config


class Baseline:
    def __init__(self, label: str = "global"):
        cfg = config.get()
        self.label        = label
        self.window_secs  = cfg["baseline_window_minutes"] * 60
        self.recalc_every = cfg["baseline_recalc_interval"]
        self.min_samples  = cfg["baseline_min_samples"]
        self.floor        = cfg["baseline_floor_rps"]

        # deque of (timestamp_second, count)
        self._samples: deque[tuple[float, float]] = deque()

        # per-hour accumulator  {0..23: [rps_samples]}
        self._hourly: dict[int, list[float]] = {}

        self._lock     = threading.Lock()
        self._mean     = self.floor
        self._stddev   = 0.0
        self._last_calc = 0.0

    # ── Public ────────────────────────────────────────────────────────────

    def update(self, ts: float, count: float):
        """Add a one-second sample."""
        with self._lock:
            self._samples.append((ts, count))
            self._evict(ts)

            hour = int(time.strftime("%H", time.localtime(ts)))
            self._hourly.setdefault(hour, []).append(count)
            # keep per-hour list bounded to avoid infinite growth
            if len(self._hourly[hour]) > 10_000:
                self._hourly[hour] = self._hourly[hour][-5_000:]

            if ts - self._last_calc >= self.recalc_every:
                self._recalculate(ts)

    def get_stats(self) -> Tuple[float, float, int]:
        """Return (mean, stddev, n_samples)."""
        with self._lock:
            return self._mean, self._stddev, len(self._samples)

    # ── Internal ──────────────────────────────────────────────────────────

    def _evict(self, now: float):
        """Remove samples older than the rolling window."""
        cutoff = now - self.window_secs
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def _recalculate(self, now: float):
        """Recompute mean/stddev; prefer hourly data when available."""
        self._last_calc = now

        hour = int(time.strftime("%H", time.localtime(now)))
        hourly = self._hourly.get(hour, [])

        if len(hourly) >= self.min_samples:
            values = hourly[-self.min_samples * 10:]  # cap to recent
            source = "hourly"
        else:
            values = [c for _, c in self._samples]
            source = "rolling"

        n = len(values)
        if n < 2:
            return

        mean   = max(sum(values) / n, self.floor)
        var    = sum((v - mean) ** 2 for v in values) / n
        stddev = math.sqrt(var)

        self._mean   = mean
        self._stddev = stddev

        from notifier import audit_log
        audit_log(
            action="BASELINE_RECALC",
            ip=self.label,
            condition=source,
            rate=round(mean, 4),
            baseline=round(stddev, 4),
            duration="n/a",
        )
