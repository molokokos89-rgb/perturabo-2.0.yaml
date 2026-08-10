import sys
import re
import json
import base64
import random

BAD_KEYWORDS = ["anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.b64decode(data).decode('utf-8', errors='ignore')

def is_valid_vless(line):
    line_lower = line.lower()
    return "security=reality" in line_lower

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

        elif line.startswith("trojan://"):
            part = line.split("://")[1].split("@")[1]
            return part.split(":")[0].split("?")[0]

        elif line.startswith("vless://"):
            if not is_valid_vless(line):
                return None
            part = line.split("://")[1].split("@")[1]
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
    try:
        with open("raw_combined.txt", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        lines = []

    clean_lines = []
    for line in lines:
        try:
            line_str = line.strip()
            if not line_str:
                continue

            if any(bad in line_str.lower() for bad in BAD_KEYWORDS):
                continue

            host = extract_host(line_str)
            if host:
                clean_lines.append(line_str)
        except Exception:
            continue

    unique_lines = list(set(clean_lines))
    random.seed(42)
    random.shuffle(unique_lines)
    
    limited_lines = unique_lines[:500]

    raw_text = "\n".join(limited_lines)
    b64_output = base64.b64encode(raw_text.encode('utf-8')).decode('utf-8')

    with open("proxy.txt", "w", encoding="utf-8") as f:
        f.write(b64_output)

if __name__ == "__main__":
    main()