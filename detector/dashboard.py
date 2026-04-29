import json, time, threading, os
from http.server import BaseHTTPRequestHandler, HTTPServer
import psutil
import config

_state = {}
_start_time = time.time()

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HNG Anomaly Detection — Live Dashboard</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;
        --danger:#f85149;--ok:#3fb950;--text:#e6edf3;--muted:#8b949e;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:20px;}
  h1{color:var(--accent);font-size:1.4rem;margin-bottom:4px;}
  .sub{color:var(--muted);font-size:.8rem;margin-bottom:20px;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px;}
  .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;}
  .card .label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}
  .card .value{font-size:1.6rem;font-weight:700;margin-top:4px;}
  .danger{color:var(--danger)!important;}
  table{width:100%;border-collapse:collapse;background:var(--card);
        border:1px solid var(--border);border-radius:8px;overflow:hidden;}
  th,td{padding:10px 14px;text-align:left;font-size:.85rem;}
  th{background:#1c2128;color:var(--muted);font-weight:600;}
  tr:not(:last-child) td{border-bottom:1px solid var(--border);}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;}
  .badge-red{background:#3d1a1a;color:var(--danger);}
  .section-title{margin:20px 0 10px;color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;}
</style>
</head>
<body>
<h1>HNG Anomaly Detection Engine</h1>
<div class="sub">Live dashboard — refreshes every 3s | Uptime: <span id="uptime">-</span></div>
<div class="grid">
  <div class="card"><div class="label">Global req/s</div><div class="value" id="rps">-</div></div>
  <div class="card"><div class="label">Baseline mean</div><div class="value" id="mean">-</div></div>
  <div class="card"><div class="label">Baseline stddev</div><div class="value" id="std">-</div></div>
  <div class="card"><div class="label">Banned IPs</div><div class="value danger" id="banned_count">-</div></div>
  <div class="card"><div class="label">CPU Usage</div><div class="value" id="cpu">-</div></div>
  <div class="card"><div class="label">Memory Usage</div><div class="value" id="mem">-</div></div>
</div>
<div class="section-title">Currently Banned IPs</div>
<table id="ban_table">
  <thead><tr><th>IP Address</th><th>Status</th></tr></thead>
  <tbody id="ban_body"><tr><td colspan="2" style="color:var(--muted)">No active bans</td></tr></tbody>
</table>
<div class="section-title">Top 10 Source IPs (last 60s)</div>
<table>
  <thead><tr><th>IP Address</th><th>Requests</th></tr></thead>
  <tbody id="top_body"><tr><td colspan="2" style="color:var(--muted)">No data yet</td></tr></tbody>
</table>
<script>
async function refresh(){
  try{
    const d = await (await fetch('/api/metrics')).json();
    document.getElementById('rps').textContent   = d.global_rps.toFixed(2);
    document.getElementById('mean').textContent  = d.baseline_mean.toFixed(2);
    document.getElementById('std').textContent   = d.baseline_std.toFixed(2);
    document.getElementById('cpu').textContent   = d.cpu_pct.toFixed(1)+'%';
    document.getElementById('mem').textContent   = d.mem_pct.toFixed(1)+'%';
    document.getElementById('banned_count').textContent = d.banned.length;
    document.getElementById('uptime').textContent = d.uptime;
    const bb = document.getElementById('ban_body');
    bb.innerHTML = d.banned.length
      ? d.banned.map(ip=>`<tr><td>${ip}</td><td><span class="badge badge-red">BLOCKED</span></td></tr>`).join('')
      : '<tr><td colspan="2" style="color:var(--muted)">No active bans</td></tr>';
    const tb = document.getElementById('top_body');
    tb.innerHTML = d.top_ips.length
      ? d.top_ips.map(([ip,cnt])=>`<tr><td>${ip}</td><td>${cnt}</td></tr>`).join('')
      : '<tr><td colspan="2" style="color:var(--muted)">No data</td></tr>';
  }catch(e){console.error(e);}
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path == "/api/metrics":
            self._metrics()
        elif self.path in ("/", "/index.html"):
            self._html()
        else:
            self.send_response(404)
            self.end_headers()

    def _html(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _metrics(self):
        det = _state.get("detector")
        if det is None:
            payload = b"{}"
        else:
            mean, std, _ = det.global_baseline.get_stats()
            up_secs = int(time.time() - _start_time)
            h, rem = divmod(up_secs, 3600)
            m, s   = divmod(rem, 60)
            payload = json.dumps({
                "global_rps":    round(det.global_rps, 3),
                "baseline_mean": round(mean, 3),
                "baseline_std":  round(std, 3),
                "banned":        sorted(det.banned),
                "top_ips":       list(det.top_ips.items()),
                "cpu_pct":       psutil.cpu_percent(interval=None),
                "mem_pct":       psutil.virtual_memory().percent,
                "uptime":        f"{h}h {m}m {s}s",
            }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)


def start(detector):
    cfg  = config.get()
    port = cfg.get("dashboard_port", 8080)
    _state["detector"] = detector
    srv = HTTPServer(("0.0.0.0", port), Handler)
    t   = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[dashboard] serving on http://0.0.0.0:{port}")
