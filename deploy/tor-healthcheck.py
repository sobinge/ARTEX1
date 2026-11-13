#!/usr/bin/env python3
"""Check the app and every configured Tor circuit without external probes."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
import urllib.request


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")


def check():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:8787/api/health", timeout=3) as response:
        if not json.load(response).get("ok"):
            raise RuntimeError("application is not ready")
    if os.environ.get("ARTEX_TRANSPARENT_TOR", "1") == "0":
        return
    key = Path("/app/jwt.key").read_bytes().strip()
    payload = b".".join((encoded({"alg": "HS256", "typ": "JWT"}),
                         encoded({"sub": "ARTEX", "exp": int(time.time()) + 30})))
    signature = base64.urlsafe_b64encode(hmac.new(key, payload, hashlib.sha256).digest()).rstrip(b"=")
    request = urllib.request.Request("http://127.0.0.1:8787/api/system/torpool",
        headers={"Authorization": "Bearer " + (payload + b"." + signature).decode()})
    with opener.open(request, timeout=3) as response:
        status = json.load(response)["status"]
    instances = status.get("instances") or []
    if not status.get("enabled") or not status.get("started") or len(instances) != status.get("size") or not instances:
        raise RuntimeError("Tor pool has not finished starting")
    for instance in instances:
        cookie = (Path(instance["data_dir"]).parent / "control_auth_cookie").read_bytes().hex()
        host, port = instance["control_addr"].rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(("AUTHENTICATE " + cookie + "\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n").encode())
            reply = b""
            while b"250 closing connection" not in reply and len(reply) < 16384:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                reply += chunk
        if not re.search(rb"PROGRESS=100(?:\s|$)", reply):
            raise RuntimeError(f"Tor slot {instance['id']} is not bootstrapped")


try:
    check()
except Exception as error:
    print(f"unhealthy: {error}", file=sys.stderr)
    sys.exit(1)
