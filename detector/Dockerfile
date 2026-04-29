FROM python:3.12-slim

# iptables is in the iptables package
RUN apt-get update && apt-get install -y iptables procps && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/detector

CMD ["python", "-u", "main.py"]
