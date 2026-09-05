#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collector.py для perturabo-2.0
- без vless (ТПУ режет)
- приоритет: hy2 > trojan > ss > vmess
- дедуп по host:port
- лимит на каждый источник
"""

import urllib.request
import base64
import re
import socket
import json
from collections import defaultdict

# --- источники (рабочие на 2026-09) ---
SOURCES = [
    # EbraSha — основные hy2 (рабочие пути)
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols/hysteria2_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols-chunks/hysteria2/EbraSha-Protocol-Chunks-hysteria2-001.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/separated-protocols/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/trojan_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/ss_configs.txt",
    # barry-far
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub2.txt",
    # прочее
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
]

# vless специально НЕ берём
PROTOCOLS = ["hy2://", "hysteria2://", "trojan://", "ss://", "vmess://"]

PROTOCOL_PRIORITY = {
    "hy2://": 0,
    "hysteria2://": 0,
    "trojan://": 1,
    "ss://": 2,
    "vmess://": 3,
}

# с hy2-источников можно брать больше
MAX_PER_SOURCE = 200
MAX_FOREIGN_TOTAL = 900

BAD_KEYWORDS = ["russia", "anycast", "offnet", "offcord", "cloudflare", "warp", "cf-"]


def fetch_url(url):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8", errors="ignore")
        # HTML-entities в ebrasha (&amp; → &)
        content = content.replace("&amp;", "&")
        if not any(proto in content for proto in PROTOCOLS):
            try:
                clean_content = content.strip().replace("\n", "").replace("\r", "")
                missing_padding = len(clean_content) % 4
                if missing_padding:
                    clean_content += "=" * (4 - missing_padding)
                clean_content = clean_content.replace("-", "+").replace("_", "/")
                content = base64.b64decode(clean_content).decode("utf-8", errors="ignore")
            except Exception:
                pass
        return content
    except Exception as e:
        print(f"  [skip] {url} ({e})")
        return ""


def safe_b64decode(data):
    data = data.strip()
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    data = data.replace("-", "+").replace("_", "/")
    return base64.b64decode(data).decode("utf-8", errors="ignore")


def extract_host_port(proxy_link):
    try:
        line = proxy_link.strip()
        # URL-decode %xx в host части ebrasha
        if "%" in line:
            try:
                from urllib.parse import unquote
                line = unquote(line)
            except Exception:
                pass
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            if "@" in part:
                host_port = part.split("@")[1]
            else:
                decoded = safe_b64decode(part)
                host_port = decoded.split("@")[1]
            host = host_port.split(":")[0].strip("[]")
            port = host_port.split(":")[1].split("/")[0].split("?")[0]
            return host, port
        if line.startswith(("trojan://", "hy2://", "hysteria2://")):
            rest = line.split("://")[1]
            if "@" in rest:
                host_port = rest.split("@")[1]
            else:
                host_port = rest
            host = host_port.split(":")[0].split("?")[0].strip("[]")
            port = host_port.split(":")[1].split("/")[0].split("?")[0].split("#")[0]
            return host, port
        if line.startswith("vmess://"):
            raw = line.split("://")[1].split("?")[0]
            data = json.loads(safe_b64decode(raw))
            return str(data.get("add", "")).strip("[]"), str(data.get("port", ""))
    except Exception:
        return None, None
    return None, None


def protocol_of(link):
    low = link.lower()
    for p in PROTOCOLS:
        if low.startswith(p):
            return p
    return "unknown://"


def is_valid_node(proxy_link):
    if any(bad in proxy_link.lower() for bad in BAD_KEYWORDS):
        return False
    if proxy_link.lower().startswith("vless://"):
        return False
    host, port = extract_host_port(proxy_link)
    if not host or not port:
        return False
    return True


def check_is_russia(host):
    if not host:
        return False
    if host.lower().endswith((".ru", ".su", ".by")):
        return True
    try:
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            ip = socket.gethostbyname(host)
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}", headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success" and data.get("countryCode") == "RU":
                return True
    except Exception:
        pass
    return False


def main():
    print("=== COLLECTOR (hy2 > trojan > ss, no vless) ===")
    foreign_map = {}
    ru_map = {}
    per_source_count = defaultdict(int)

    for source in SOURCES:
        print(f"Source: {source}")
        data = fetch_url(source)
        if not data:
            continue
        seen_in_source = set()
        for line in data.splitlines():
            line = line.strip()
            if not any(line.startswith(p) for p in PROTOCOLS):
                continue
            if not is_valid_node(line):
                continue
            host, port = extract_host_port(line)
            key = f"{host}:{port}"
            if key in seen_in_source:
                continue
            if per_source_count[source] >= MAX_PER_SOURCE:
                break
            seen_in_source.add(key)
            per_source_count[source] += 1

            prio = PROTOCOL_PRIORITY.get(protocol_of(line), 99)
            target = ru_map if check_is_russia(host) else foreign_map
            if key not in target or prio < PROTOCOL_PRIORITY.get(protocol_of(target[key]), 99):
                target[key] = line

        print(f"  taken from source: {per_source_count[source]}")

    def sort_key(link):
        return (PROTOCOL_PRIORITY.get(protocol_of(link), 99), link)

    foreign_list = sorted(foreign_map.values(), key=sort_key)[:MAX_FOREIGN_TOTAL]
    ru_list = sorted(ru_map.values(), key=sort_key)

    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(foreign_list) + "\n")
    with open("ru_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ru_list) + "\n")

    hy2_n = sum(1 for x in foreign_list if protocol_of(x) in ("hy2://", "hysteria2://"))
    print(f"Foreign: {len(foreign_list)} (hy2={hy2_n})")
    print(f"RU nodes: {len(ru_list)}")
    print("OK → raw_combined.txt, ru_nodes.txt")


if __name__ == "__main__":
    main()
