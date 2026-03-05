import json
import sys
import re

data = json.load(sys.stdin)
hits = data.get('rawResponse', {}).get('hits', {}).get('hits', [])

# Extract all string values from nested structures
all_strings = []

def extract_strings(obj):
    if isinstance(obj, str):
        all_strings.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            extract_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            extract_strings(item)

for hit in hits:
    extract_strings(hit)

# Search for flag-like patterns
flag_patterns = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'[A-Z0-9]{32,}',
    r'[a-f0-9]{64}',
]

print("=== SEARCHING FOR FLAGS ===")
for s in all_strings:
    s_str = str(s)
    if 'flag' in s_str.lower() or 'ctf' in s_str.lower():
        print(f"CONTAINS FLAG KEYWORD: {s_str[:500]}")
    for pattern in flag_patterns:
        matches = re.findall(pattern, s_str, re.I)
        if matches:
            for m in matches:
                if len(m) > 10:
                    print(f"PATTERN MATCH ({pattern}): {m}")

