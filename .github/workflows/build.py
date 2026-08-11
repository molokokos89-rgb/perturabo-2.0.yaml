import json
import urllib.request
import re

EXTERNAL_REJECT_URLS = [
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/5kms/oisd-singbox/main/domain_suffix_reject.txt"
]

def read_local_list(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

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

rules = []

direct_domains = read_local_list('direct.txt')
if direct_domains:
    rules.append({
        "action": "direct",
        "domain_suffix": sorted(list(set(direct_domains)))
    })

proxy_domains = read_local_list('proxy.txt')
if proxy_domains:
    rules.append({
        "action": "proxy",
        "domain_suffix": sorted(list(set(proxy_domains)))
    })

reject_domains = set(read_local_list('reject.txt'))

for url in EXTERNAL_REJECT_URLS:
    ext_domains = fetch_external_domains(url)
    reject_domains.update(ext_domains)

if reject_domains:
    rules.append({
        "action": "reject",
        "domain_suffix": sorted(list(reject_domains))
    })

config = {
    "version": 2,
    "rules": rules
}

with open('my_rules.json', 'w', encoding='utf-8') as f:
    json.dump(config, f, indent=2, ensure_ascii=False)

print(f"Done! REJECT contains {len(reject_domains)} domains.")