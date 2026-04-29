import json, time, os, threading
from datetime import datetime, timezone
from urllib import request as urlreq
import config

_slack_lock = threading.Lock()
_audit_lock = threading.Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def send_slack(*, event: str, ip: str, condition: str,
               rate: float, baseline: float, duration: str):
    cfg = config.get()
    webhook = os.environ.get("SLACK_WEBHOOK_URL") or cfg.get("slack_webhook_url", "")
    if not webhook or "YOUR" in webhook:
        print(f"[notifier] Slack not configured — would send: {event} ip={ip}")
        return

    emoji = {
        "BAN":            ":rotating_light:",
        "UNBAN":          ":white_check_mark:",
        "GLOBAL_ANOMALY": ":warning:",
    }.get(event, ":bell:")

    text = (
        f"{emoji} *{event}*\n"
        f">*IP:* `{ip}`\n"
        f">*Condition:* {condition}\n"
        f">*Current rate:* {rate:.2f} req/s\n"
        f">*Baseline mean:* {baseline:.2f} req/s\n"
        f">*Duration:* {duration}\n"
        f">*Timestamp:* {_ts()}"
    )

    payload = json.dumps({"text": text}).encode()
    req = urlreq.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _slack_lock:
            with urlreq.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    print(f"[notifier] Slack HTTP {resp.status}")
    except Exception as e:
        print(f"[notifier] Slack error: {e}")


def audit_log(action: str, ip: str, condition: str,
              rate: float, baseline: float, duration: str):
    cfg  = config.get()
    path = cfg.get("audit_log", "/var/log/detector/audit.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    line = (
        f"[{_ts()}] {action} {ip} | {condition} | "
        f"rate={rate:.4f} | baseline={baseline:.4f} | duration={duration}\n"
    )
    with _audit_lock:
        with open(path, "a") as f:
            f.write(line)
    print(f"[audit] {line.strip()}")

