import urllib.request
import base64

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vm.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mftaw/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs/main/sub/mix",
    "https://raw.githubusercontent.com/erfan-ahmadix/V2rayCollector/main/sub/mix"
]

def decode_text(text):
    text = text.strip()
    if any(proto in text for proto in ["ss://", "vmess://", "trojan://"]):
        return text
    try:
        missing_padding = len(text) % 4
        if missing_padding:
            text += '=' * (4 - missing_padding)
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return text

def fetch_url(url):
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return decode_text(content)
    except Exception as e:
        print(f"Ошибка загрузки источника {url}: {e}")
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
    print(f"Успешно собрано уникальных узлов: {len(unique_nodes)}")

    with open("raw_combined.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(unique_nodes) + "\n")

if __name__ == "__main__":
    main()