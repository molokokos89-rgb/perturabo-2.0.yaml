import sys
import re
import json
import base64
import urllib.request
import urllib.parse
import os

BAD_KEYWORDS = ["anycast", "fixnet", "fixcord", "cloudflare", "warp", "cf-"]

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

def process_extracted_items(items, target_list):
    if isinstance(items, list):
        for item in items:
            if isinstance(item, str):
                target_list.append(item)
    elif isinstance(items, str):
        target_list.append(items)

def load_domains_from_sources():
    if not os.path.exists("urls_test.txt"):
        return []
    
    with open("urls_test.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    all_extracted = []
    
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                if url.endswith(".json"):
                    data = json.loads(response.read().decode('utf-8'))
                    if "payload" in data:
                        process_extracted_items(data["payload"], all_extracted)
                    if "rules" in data and isinstance(data["rules"], list):
                        for rule in data["rules"]:
                            if isinstance(rule, dict):
                                if "domain" in rule: process_extracted_items(rule["domain"], all_extracted)
                                if "domain_suffix" in rule: process_extracted_items(rule["domain_suffix"], all_extracted)
                else:
                    lines = response.read().decode('utf-8', errors='ignore').splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("//"):
                            domain = line.split(",")[-1] if "," in line else line
                            all_extracted.append(domain)
        except:
            pass

    clean_domains = set()
    for d in all_extracted:
        if not isinstance(d, str): continue
        d_clean = d.strip().split(",")[-1] if "," in d else d.strip()
        d_clean = d_clean.replace("+.", "")
        if d_clean and "." in d_clean and len(d_clean) > 3:
            clean_domains.add(d_clean.lower())

    return sorted(list(clean_domains))

def main():
    try:
        with open("raw_combined.txt", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        lines = []

    clean_lines = []
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("vless://"):
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

    blocked_list = load_domains_from_sources()

    with open("My_rules_BLOCKED_test.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(blocked_list) + "\n")

if __name__ == "__main__":
    main()
