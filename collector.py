import urllib.request
import base64

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
]

PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "hysteria2://"]

def fetch_url(url):
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            
            # Если в тексте НЕТ ни одного открытого протокола — пробуем расшифровать Base64
            if not any(proto in content for proto in PROTOCOLS):
                try:
                    # Чистим от лишних пробелов и переносов перед декодированием
                    clean_content = content.strip().replace("\n", "").replace("\r", "")
                    missing_padding = len(clean_content) % 4
                    if missing_padding:
                        clean_content += '=' * (4 - missing_padding)
                    content = base64.b64decode(clean_content).decode('utf-8', errors='ignore')
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
                if any(line.startswith(proto) for proto in PROTOCOLS):
                    raw_nodes.append(line)

    unique_nodes = list(set(raw_nodes))
    
    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_nodes) + "\n")

if __name__ == "__main__":
    main()