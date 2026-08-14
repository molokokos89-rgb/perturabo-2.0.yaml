import json
import urllib.request
import re

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
        return {"version": 2, "rules": []}

def fetch_external_domains(url):
    domains = set()
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
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
rules = data.get('rules', [])

external_domains = set()
for url in EXTERNAL_REJECT_URLS:
    external_domains.update(fetch_external_domains(url))

if rules:
    for rule in rules:
        existing_suffixes = set(rule.get('domain_suffix', []))
        existing_suffixes.update(external_domains)
        rule['domain_suffix'] = sorted(list(existing_suffixes))
        if 'action' not in rule:
            rule['action'] = 'reject'
else:
    rules = [{
        "action": "reject",
        "domain_suffix": sorted(list(external_domains))
    }]

data['rules'] = rules

with open('reject_rules.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"reject_rules.json updated!")
