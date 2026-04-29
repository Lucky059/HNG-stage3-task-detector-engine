HNG Anomaly Detection Engine
📌 Overview
The HNG Anomaly Detection Engine monitors Nginx access logs in real time, detects suspicious traffic patterns (e.g. spikes, repeated errors, abnormal request rates), and automatically responds by:

🚨 Sending alerts to Slack via a webhook

🚫 Banning offending IPs using firewall rules

✅ Unbanning IPs once traffic normalizes

It also provides a dashboard (default: http://<server-ip>:8080) for visualizing anomalies and baselines.

⚙️ Architecture
Nginx → Logs requests in JSON format (/var/log/nginx/hng-access.log)

Detector Engine → Watches logs, recalculates baselines, detects anomalies

Slack Webhook → Receives alerts when anomalies occur

Firewall (iptables/ufw) → Enforces bans/unbans

Dashboard → Displays anomaly metrics and status

🚀 Setup
Run Nginx with JSON logging  
Configure nginx.conf to log in JSON format to /var/log/nginx/hng-access.log.

Start the Detector Engine

bash
python3 detector.py
or run via Docker Compose.

Configure Slack Webhook  
Add your Slack webhook URL in config.yaml or environment variable:

yaml
slack_webhook: https://hooks.slack.com/services/XXXX/YYYY/ZZZZ
Firewall Permissions  
Ensure the engine has permission to run iptables or ufw commands.

🖥️ Dashboard
Default port: 8080

Accessible at: http://<server-ip>:8080

Shows rolling baselines, anomaly rates, and ban/unban events.

🔒 Ban/Unban Logic
When anomaly detected → ban IP via firewall + Slack alert

When anomaly clears → unban IP + Slack notification

Example Slack messages:

🚫 Banned IP 203.0.113.45 due to anomaly

✅ Unbanned IP 203.0.113.45 after anomaly cleared

🧪 Testing
You can safely simulate anomalies without launching real attacks:

ApacheBench (ab):

bash
ab -n 1000 -c 50 http://<server-ip>/
wrk:

bash
wrk -t4 -c100 -d30s http://<server-ip>/
