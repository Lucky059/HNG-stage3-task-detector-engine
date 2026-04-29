import subprocess


def _run(cmd: list[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[blocker] iptables error: {e.stderr.decode().strip()}")
        return False


def block_ip(ip: str):
    print(f"[blocker] BLOCKING {ip}")
    _run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])


def unblock_ip(ip: str):
    print(f"[blocker] UNBLOCKING {ip}")
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
