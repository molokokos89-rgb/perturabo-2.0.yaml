import urllib.request
import base64
import re
import socket
import json
from urllib.parse import unquote

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
]

# vmess/trojan убраны — с них почти нет живых, anycast в основном vmess
PROTOCOLS = ["ss://", "hy2://", "hysteria2://", "vless://"]

BAD_KEYWORDS = [
    "anycast", "any-cast", "any_cast",
    "russia", "russian", "росси", "москва", "moscow",
    "offnet", "offcord", "fixnet", "fixcord",
]


def safe_b64decode(data):
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data).decode("utf-8", errors="ignore")


def fetch_url(url):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8", errors="ignore")
        if not any(proto in content for proto in PROTOCOLS):
            try:
                clean_content = content.strip().replace("\n", "").replace("\r", "")
                content = safe_b64decode(clean_content)
            except Exception:
                pass
        return content
    except Exception:
        return ""


def node_display_name(proxy_link):
    """Имя ноды: #remark или vmess.ps (там прячется Anycast-IP)."""
    parts = [proxy_link]
    try:
        if "#" in proxy_link:
            parts.append(unquote(proxy_link.split("#", 1)[1]))
        if proxy_link.startswith("vmess://"):
            raw = proxy_link.split("://", 1)[1].split("#")[0]
            data = json.loads(safe_b64decode(raw))
            parts.append(str(data.get("ps", "")))
            parts.append(str(data.get("add", "")))
    except Exception:
        pass
    return " ".join(parts).lower()


def has_bad_keyword(proxy_link):
    hay = node_display_name(proxy_link)
    return any(bad in hay for bad in BAD_KEYWORDS)


def extract_ip_or_domain(proxy_link):
    try:
        clean_link = re.sub(r"^[a-zA-Z0-9\-\.]+://", "", proxy_link)
        if "@" in clean_link:
            server_part = clean_link.split("@")[-1]
        else:
            server_part = clean_link
        server_address = re.split(r"[:/?#]", server_part)
        return server_address[0].strip()
    except Exception:
        return None


def is_valid_reality(proxy_link):
    """Только чистый VLESS Reality (security=reality + pbk). SNI не баним."""
    if not proxy_link.startswith("vless://"):
        return True
    low = proxy_link.lower()
    if "security=reality" not in low or "pbk=" not in low:
        return False
    return True


def check_is_russia(host):
    if not host:
        return False
    if host.lower().endswith((".ru", ".su", ".by", ".рф")):
        return True
    try:
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            ip = socket.gethostbyname(host)
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "success" and data.get("countryCode") == "RU":
                return True
    except Exception:
        pass
    return False


def main():
    raw_nodes = []
    for source in SOURCES:
        data = fetch_url(source)
        if not data:
            print(f"[skip] {source}")
            continue
        n = 0
        for line in data.splitlines():
            line = line.strip()
            if not any(line.startswith(proto) for proto in PROTOCOLS):
                continue
            if has_bad_keyword(line):
                continue
            if not is_valid_reality(line):
                continue
            raw_nodes.append(line)
            n += 1
        print(f"taken {n} from {source}")

    unique_nodes = list(set(raw_nodes))
    foreign_nodes = []
    ru_nodes = []

    for node in unique_nodes:
        host = extract_ip_or_domain(node)
        if check_is_russia(host):
            ru_nodes.append(node)
        else:
            foreign_nodes.append(node)

    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(foreign_nodes) + "\n")
    with open("ru_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(ru_nodes) + "\n")
    print(f"foreign={len(foreign_nodes)} ru={len(ru_nodes)}")


if __name__ == "__main__":
    main()
