import sys
import re
import json
import base64
import socket
import urllib.request
import urllib.parse
import subprocess
import os

BAD_KEYWORDS = ["russia", "anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def extract_host(line):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            if "@" in part:
                host_port = part.split("@")[1]
            else:
                decoded = safe_b64decode(part)
                host_port = decoded.split("@")[1]
            return host_port.split(":")[0]
        elif line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://")):
            if "@" in line:
                part = line.split("://")[1].split("@")[1]
                return part.split(":")[0].split("?")[0]
            else:
                part = line.split("://")[1]
                return part.split(":")[0].split("?")[0]
        elif line.startswith("vmess://"):
            b64_str = line.split("://")[1]
            decoded = safe_b64decode(b64_str)
            data = json.loads(decoded)
            return data.get("add")
    except Exception:
        return None
    return None

def main():
    if os.path.exists("raw_combined.txt"):
        try:
            with open("raw_combined.txt", "r", encoding="utf-8") as f:
                lines = f.readlines()
            clean_lines = []
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                if any(bad in line_str.lower() for bad in BAD_KEYWORDS):
                    continue
                host = extract_host(line_str)
                if host:
                    clean_lines.append(line_str)
            unique_lines = sorted(list(set(clean_lines)))
            raw_text = "\n".join(unique_lines)
            b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')
            with open("proxy.txt", "w", encoding="utf-8") as f:
                f.write(b64_output)
        except Exception:
            pass

    if os.path.exists("ru_nodes.txt"):
        try:
            with open("ru_nodes.txt", "r", encoding="utf-8") as f:
                ru_lines = [l.strip() for l in f if l.strip()]
            if ru_lines:
                ru_raw_text = "\n".join(ru_lines)
                ru_b64 = base64.b64encode(ru_raw_text.encode('utf-8')).decode('utf-8')
                with open("ru_proxies.txt", "w", encoding="utf-8") as rf:
                    rf.write(ru_b64)
        except Exception:
            pass

if __name__ == "__main__":
    main()
