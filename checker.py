#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
checker.py для perturabo-2.0
Чистит raw_combined.txt / ru_nodes.txt → proxy.txt (base64) и ru_proxies.txt (base64)
Дедуп host:port, без vless, без bad keywords.
"""

import os
import re
import json
import base64

BAD_KEYWORDS = ["russia", "anycast", "offnet", "offcord", "cloudflare", "warp", "cf-"]


def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data).decode("utf-8", errors="ignore")


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
                host_port = safe_b64decode(part).split("@")[1]
            host = host_port.split(":")[0].strip("[]")
            port = host_port.split(":")[1].split("/")[0].split("?")[0]
            return host, port
        if line.startswith(("trojan://", "hy2://", "hysteria2://", "vless://")):
            rest = line.split("://")[1]
            host_port = rest.split("@")[1] if "@" in rest else rest
            host = host_port.split(":")[0].split("?")[0].strip("[]")
            port = host_port.split(":")[1].split("/")[0].split("?")[0].split("#")[0]
            return host, port
        if line.startswith("vmess://"):
            data = json.loads(safe_b64decode(line.split("://")[1].split("?")[0]))
            return str(data.get("add", "")).strip("[]"), str(data.get("port", ""))
    except Exception:
        return None, None
    return None, None


def clean_list(lines):
    best = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("vless://"):
            continue
        if any(bad in line.lower() for bad in BAD_KEYWORDS):
            continue
        host, port = extract_host_port(line)
        if not host or not port:
            continue
        key = f"{host}:{port}"
        # сохраняем первую (collector уже отсортировал по приоритету)
        if key not in best:
            best[key] = line
    return list(best.values())


def write_b64(path, lines):
    raw = "\n".join(sorted(lines))
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        f.write(b64)
    print(f"  {path}: {len(lines)} nodes")


def main():
    print("=== CHECKER ===")
    if os.path.exists("raw_combined.txt"):
        with open("raw_combined.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()
        clean = clean_list(lines)
        write_b64("proxy.txt", clean)
    else:
        print("  raw_combined.txt not found")

    if os.path.exists("ru_nodes.txt"):
        with open("ru_nodes.txt", "r", encoding="utf-8") as f:
            ru_lines = [l.strip() for l in f if l.strip()]
        clean_ru = clean_list(ru_lines)
        write_b64("ru_proxies.txt", clean_ru)
    else:
        print("  ru_nodes.txt not found")

    print("OK")


if __name__ == "__main__":
    main()
