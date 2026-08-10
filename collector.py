import urllib.request
import base64

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
]

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            if not any(proto in content for proto in ["ss://", "vmess://", "trojan://"]):
                try:
                    content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                except Exception:
                    pass
            return content
    except Exception:
        return ""

def main():
    raw_nodes = []
    for source in SOURCES:
        data = fetch_url(source)
        if data:
            for line in data.splitlines():
                line = line.strip()
                if any(line.startswith(proto) for proto in ["ss://", "vmess://", "trojan://"]):
                    raw_nodes.append(line)

    unique_nodes = list(set(raw_nodes))
    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_nodes) + "\n")

if __name__ == "__main__":
    main()
