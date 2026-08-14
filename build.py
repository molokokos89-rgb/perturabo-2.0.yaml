import json
import urllib.request
import re
import os
import subprocess

EXTERNAL_REJECT_URLS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/5kms/oisd-singbox/main/domain_suffix_reject.txt",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/russia/runetfreedom/sing-box/rule-set-geosite/geosite-adblock.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/russia/runetfreedom/sing-box/rule-set-geosite/geosite-adblockplus.srs"
]

def load_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return {"version": 1, "rules": []}

def fetch_external_domains(url, index):
    domains = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        if url.endswith(".srs"):
            srs_file = f"temp_reject_{index}.srs"
            json_file = f"temp_reject_{index}.json"
            with urllib.request.urlopen(req, timeout=15) as response:
                with open(srs_file, "wb") as out:
                    out.write(response.read())
            subprocess.run(["sing-box", "rule-set", "decompile", srs_file, "--output", json_file], check=True)
            if os.path.exists(json_file):
                with open(json_file, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                    for rule in data.get("rules", []):
                        if "domain" in rule: domains.update(rule["domain"])
                        if "domain_suffix" in rule: domains.update(rule["domain_suffix"])
            if os.path.exists(srs_file): os.remove(srs_file)
            if os.path.exists(json_file): os.remove(json_file)
        else:
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('!'):
                        continue
                    cleaned = re.sub(r'^[|]*', '', line)
                    cleaned = re.sub(r'[\^$/].*$', '', cleaned)
                    if cleaned and '.' in cleaned and not cleaned.startswith('127.') and not cleaned.startswith('0.'):
                        domains.add(cleaned)
    except Exception as e:
        print(f"Error loading {url}: {e}")
    return domains

data = load_json('reject_rules.json')

external_items = set()
for index, url in enumerate(EXTERNAL_REJECT_URLS):
    external_items.update(fetch_external_domains(url, index))

final_domains = set()
final_ips = set()

ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

for item in external_items:
    item_clean = item.strip().replace("`", "").replace("*.", "")
    if ip_pattern.match(item_clean):
        final_ips.add(f"{item_clean}/32")
    else:
        final_domains.add(item)

if 'rules' in data and data['rules']:
    for rule in data['rules']:
        if 'domain_suffix' in rule:
            for item in rule['domain_suffix']:
                item_clean = item.strip().replace("`", "").replace("*.", "")
                if ip_pattern.match(item_clean):
                    final_ips.add(f"{item_clean}/32")
                else:
                    final_domains.add(item)
        if 'ip_cidr' in rule:
            final_ips.update(rule['ip_cidr'])

# Собираем строго под синтаксис Версии 1 (один общий блок правил)
rule_dict = {}
if final_domains:
    rule_dict["domain_suffix"] = sorted(list(final_domains))
if final_ips:
    rule_dict["ip_cidr"] = sorted(list(final_ips))

data['version'] = 1
data['rules'] = [rule_dict] if rule_dict else []

with open('reject_rules.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"reject_rules.json updated successfully in version 1 format!")
