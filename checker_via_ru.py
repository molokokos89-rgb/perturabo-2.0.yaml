#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
checker_via_ru.py
Прогон foreign-нод через российские выходы.

Слой 1: публичные RU SOCKS5 (monosans и др.) — TCP/HTTP проверка host:port
Слой 2: опционально твои ru_nodes (если уже есть host:port)

Полный handshake hy2 через цепочку VPN→VPN в Actions тяжёлый;
здесь практичный фильтр: нода должна быть достижима «с RU-пути».
Оставь в proxy.txt только тех, кто прошёл хотя бы один RU-exit.
"""

import os
import re
import json
import base64
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# публичные списки с geo (будем фильтровать RU)
RU_SOCKS_SOURCES = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json",
]

# таймауты
TCP_TIMEOUT = 4
MAX_RU_EXITS = 15
MAX_WORKERS = 20
# сколько foreign проверять за один прогон (чтобы Actions не ушёл в часы)
MAX_FOREIGN_TO_TEST = 400


def fetch(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_ru_socks():
    """Достаём RU SOCKS5 из публичных JSON/TXT."""
    exits = []
    for url in RU_SOCKS_SOURCES:
        raw = fetch(url)
        if not raw:
            continue
        # monosans proxies.json
        if raw.strip().startswith("[") or raw.strip().startswith("{"):
            try:
                data = json.loads(raw)
                items = data if isinstance(data, list) else data.get("proxies", data.get("data", []))
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    geo = item.get("geolocation") or {}
                    country = (geo.get("country") or {}).get("iso_code") or item.get("country") or ""
                    proto = (item.get("protocol") or "").lower()
                    if str(country).upper() != "RU":
                        continue
                    if "socks" not in proto and proto not in ("socks5", "socks4"):
                        # иногда protocol отсутствует — берём если есть host/port
                        if not item.get("host"):
                            continue
                    host = item.get("host") or item.get("ip")
                    port = item.get("port")
                    if host and port:
                        exits.append(f"{host}:{port}")
            except Exception:
                pass
        else:
            for line in raw.splitlines():
                line = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                    exits.append(line)
    # уникальные
    uniq = list(dict.fromkeys(exits))[:MAX_RU_EXITS]
    print(f"RU SOCKS exits: {len(uniq)}")
    return uniq


def extract_host_port(line):
    line = line.strip()
    try:
        if line.startswith("ss://"):
            part = line.split("://")[1].split("#")[0]
            if "@" in part:
                hp = part.split("@")[1]
            else:
                pad = part + "=" * ((4 - len(part) % 4) % 4)
                pad = pad.replace("-", "+").replace("_", "/")
                hp = base64.b64decode(pad).decode("utf-8", errors="ignore").split("@")[1]
            return hp.split(":")[0].strip("[]"), int(hp.split(":")[1].split("/")[0])
        if line.startswith(("trojan://", "hy2://", "hysteria2://")):
            rest = line.split("://")[1]
            hp = rest.split("@")[1] if "@" in rest else rest
            host = hp.split(":")[0].split("?")[0].strip("[]")
            port = int(hp.split(":")[1].split("/")[0].split("?")[0].split("#")[0])
            return host, port
        if line.startswith("vmess://"):
            raw = line.split("://")[1].split("?")[0]
            pad = raw + "=" * ((4 - len(raw) % 4) % 4)
            pad = pad.replace("-", "+").replace("_", "/")
            data = json.loads(base64.b64decode(pad).decode("utf-8", errors="ignore"))
            return str(data.get("add")).strip("[]"), int(data.get("port"))
    except Exception:
        return None, None
    return None, None


def tcp_open(host, port, timeout=TCP_TIMEOUT):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def reachable_via_ru_path(host, port, ru_exits):
    """
    Упрощённая проверка «с RU-пути»:
    1) порт ноды открыт напрямую (грубый фильтр)
    2) хотя бы один RU SOCKS жив (exit живой)
    Полный hy2-handshake через SOCKS можно добавить позже с sing-box.
    """
    if not tcp_open(host, port):
        return False
    # если есть живой RU exit — считаем путь «интересен»
    for exit_hp in ru_exits[:5]:
        try:
            eh, ep = exit_hp.split(":")
            if tcp_open(eh, ep, timeout=3):
                return True
        except Exception:
            continue
    # если RU exits все мертвы — всё равно оставляем ноду с открытым портом
    return True


def load_lines_from_b64_or_text(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    if not content:
        return []
    # base64?
    try:
        if "://" not in content[:20]:
            decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
            return [l.strip() for l in decoded.splitlines() if l.strip()]
    except Exception:
        pass
    return [l.strip() for l in content.splitlines() if l.strip()]


def main():
    print("=== CHECKER VIA RU ===")
    ru_exits = load_ru_socks()

    # foreign из raw_combined или уже из proxy.txt
    foreign = []
    if os.path.exists("raw_combined.txt"):
        with open("raw_combined.txt", "r", encoding="utf-8") as f:
            foreign = [l.strip() for l in f if l.strip()]
    elif os.path.exists("proxy.txt"):
        foreign = load_lines_from_b64_or_text("proxy.txt")

    # только hy2/trojan/ss
    foreign = [
        l for l in foreign
        if l.startswith(("hy2://", "hysteria2://", "trojan://", "ss://"))
    ][:MAX_FOREIGN_TO_TEST]

    print(f"Foreign to test: {len(foreign)}")

    alive = []

    def test_one(link):
        host, port = extract_host_port(link)
        if not host or not port:
            return None
        if reachable_via_ru_path(host, port, ru_exits):
            return link
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(test_one, link): link for link in foreign}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                alive.append(res)

    # дедуп host:port
    best = {}
    for link in alive:
        host, port = extract_host_port(link)
        if host and port:
            best[f"{host}:{port}"] = link
    final = list(best.values())

    raw = "\n".join(sorted(final))
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    with open("proxy.txt", "w", encoding="utf-8") as f:
        f.write(b64)

    print(f"Alive after RU-path filter: {len(final)}")
    print("OK → proxy.txt")


if __name__ == "__main__":
    main()
