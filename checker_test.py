import sys
import re
import json
import base64

BAD_KEYWORDS = ["anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-", "vless://"]

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
                decoded = base64.b64decode(part + "==").decode('utf-8', errors='ignore')
                host_port = decoded.split("@")[1]
            return host_port.split(":")[0]

        elif line.startswith("trojan://"):
            part = line.split("://")[1].split("@")[1]
            return part.split(":")[0].split("?")[0]

        elif line.startswith("vmess://"):
            b64_str = line.split("://")[1]
            decoded = base64.b64decode(b64_str + "==").decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            return data.get("add")
    except Exception:
        return None
    return None

def main():
    with open("raw_combined.txt", "r", encoding="utf-8", errors="ignore") as f:
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
    with open("proxy_test.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines) + "\n")

if __name__ == "__main__":
    main()
