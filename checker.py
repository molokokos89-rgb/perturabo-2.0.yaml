import sys
import re
import json
import base64
import random
import socket
from concurrent.futures import ThreadPoolExecutor

BAD_KEYWORDS = [
    "anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-",
    "irc", "bot", "free", "pub"
]

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def is_valid_vless(line):
    line_lower = line.lower()
    return any(sec in line_lower for sec in ["security=reality", "security=tls", "type=ws", "type=grpc"])

def extract_host_port(line):
    line = line.strip()
    if not line:
        return None, None
    try:
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            if "@" in part:
                host_port = part.split("@")[1]
            else:
                decoded = safe_b64decode(part)
                host_port = decoded.split("@")[1]
            hp = host_port.split("?")[0]
            host, port = hp.split(":")
            return host, int(port)

        elif line.startswith("trojan://"):
            part = line.split("://")[1].split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")
            return host, int(port)

        elif line.startswith("vless://"):
            if not is_valid_vless(line):
                return None, None
            part = line.split("://")[1].split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")
            return host, int(port)
    except Exception:
        return None, None
    return None, None

def check_node(line):
    if any(bad in line.lower() for bad in BAD_KEYWORDS):
        return None

    host, port = extract_host_port(line)
    if not host or not port:
        return None

    try:
        ip = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return line
    except Exception:
        pass
    return None

def main():
    try:
        with open("raw_combined.txt", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        lines = []

    lines = list(set([line.strip() for line in lines if line.strip()]))
    
    random.seed(42)
    random.shuffle(lines)
    sample_lines = lines[:3000]

    alive_nodes = []
    with ThreadPoolExecutor(max_workers=150) as executor:
        results = executor.map(check_node, sample_lines)
        for res in results:
            if res:
                alive_nodes.append(res)

    limited_lines = alive_nodes[:300]

    raw_text = "\n".join(limited_lines)
    b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')

    with open("proxy.txt", "w", encoding="utf-8") as f:
        f.write(b64_output)

if __name__ == "__main__":
    main()