"""
main.py — entry point for the HNG anomaly detection daemon.

Wires together:
  monitor   → tail the nginx log
  detector  → sliding window + baseline + anomaly detection
  unbanner  → backoff unban scheduler (background thread)
  dashboard → live metrics HTTP server (background thread)

The main thread sits in a tight loop reading log lines and feeding them
to the detector.  All blocking I/O (Slack, iptables) happens on
short-lived sub-operations that are fast enough not to stall the loop.
"""

import threading, time, sys
import config
from monitor   import tail_log
from detector  import Detector
from unbanner  import Unbanner
import dashboard


def main():
    cfg = config.get()
    print("[main] HNG Anomaly Detection Engine starting…")
    print(f"[main] Watching: {cfg['log_path']}")
    print(f"[main] Dashboard: http://0.0.0.0:{cfg['dashboard_port']}")

    det = Detector()

    # Auto-unbanner runs in a background thread
    unbanner = Unbanner(det.banned)
    ub_thread = threading.Thread(target=unbanner.run, daemon=True, name="unbanner")
    ub_thread.start()

    # Patch the blocker so newly banned IPs are registered with the unbanner
    import blocker as _blk
    _orig_block = _blk.block_ip
    def _patched_block(ip):
        _orig_block(ip)
        unbanner.register_ban(ip)
    _blk.block_ip = _patched_block

    # Dashboard runs in a background thread
    dashboard.start(det)

    # Main loop: read log lines → feed detector
    count = 0
    for entry in tail_log():
        det.process(entry)
        count += 1
        if count % 500 == 0:
            mean, std, n = det.global_baseline.get_stats()
            print(f"[main] processed={count} rps={det.global_rps:.2f} "
                  f"mean={mean:.2f} std={std:.2f} banned={len(det.banned)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[main] shutting down")
        sys.exit(0)
    


