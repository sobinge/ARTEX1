#!/usr/bin/env python3
"""Verify Docker Tor routing and fail-closed behavior without configuring agents.

Uses only Python's standard library on the host. The running ARTEX container
provides curl, Python and Node. A short-lived JWT is signed with the existing
local jwt.key; neither the token nor key is written to the report. The script
temporarily stops the Tor pool and always attempts to restart it in finally.

Run from a host with access to the project's Docker engine:
    python3 test/regression/docker_tor_check.py --core-only --output /tmp/tor-check.json

To verify Tor routing without contacting the callback service:
    python3 test/regression/docker_tor_check.py --core-only --output /tmp/tor-core-check.json
The exit code reflects the selected scope; core-only never certifies callbacks.
Use --probe-attempts 3 to retry transient network failures of positive official
Tor GET probes on the same route. Callback and fail-closed probes never retry.

To verify HTTP callbacks using an existing Webhook.site token:
    python3 test/regression/docker_tor_check.py --callback-provider webhook-site --callback-token UUID
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


TOR_CHECK = "https://check.torproject.org/api/ip"
TOR_EXITS = "https://check.torproject.org/torbulkexitlist"
CURL_NETWORK_FAILURES = {5, 6, 7, 18, 28, 35, 52, 55, 56, 97}


def jwt_for(key_path: Path) -> str:
    key = key_path.read_bytes().strip()
    if len(key) < 32:
        raise ValueError("JWT signing key is missing or shorter than 32 bytes")

    def encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    now = int(time.time())
    head = encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = encode(json.dumps({"sub": "ARTEX", "iat": now, "exp": now + 3600}).encode())
    signed = f"{head}.{body}"
    signature = encode(hmac.new(key, signed.encode(), hashlib.sha256).digest())
    return f"{signed}.{signature}"


def safe_proxy(proxy: str) -> str:
    parsed = urllib.parse.urlsplit(proxy)
    address = parsed.hostname or ""
    if parsed.port:
        address += f":{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, address, parsed.path, "", ""))


def tor_plan(resolved: dict) -> bool:
    """Provider identity is separate from HTTP/SOCKS transport protocol.

    Older servers have no provider field; their explicit Tor plan remains
    compatible, but a generic SOCKS endpoint is never taken as proof of Tor.
    """
    if "provider" in resolved:
        return resolved["provider"] == "tor"
    return resolved.get("mode") == "tor" and resolved.get("is_tor") is True


def callback_events(payload: dict, provider: str) -> list[dict]:
    """Normalize HTTP receipts while keeping DNS resolver IPs out of exit checks."""
    if provider == "cvss":
        return [row for row in payload.get("requests_history") or []
                if str(row.get("protocol", "")).upper() in {"HTTP", "HTTPS"}]
    if provider != "webhook-site":
        raise ValueError("Unsupported callback provider: " + provider)
    if not isinstance(payload.get("data"), list):
        raise ValueError("Webhook.site log response is missing the data list")
    events = []
    for row in payload["data"]:
        # DNSHook's source IP belongs to a recursive resolver, not an HTTP exit.
        if row.get("type") != "web":
            continue
        url = str(row.get("url", ""))
        scheme = urllib.parse.urlsplit(url).scheme.upper()
        if scheme not in {"HTTP", "HTTPS"}:
            continue
        headers = []
        for name, values in (row.get("headers") or {}).items():
            for value in values if isinstance(values, list) else [values]:
                headers.append(f"{name}: {value}")
        events.append({
            "id": row.get("uuid"), "provider": provider, "protocol": scheme,
            "ip": row.get("ip"), "timestamp": row.get("created_at"),
            "dump": f"{row.get('method', 'GET')} {url}\n" + "\n".join(headers)
                    + "\n\n" + str(row.get("content") or ""),
        })
    return events


class Verification:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.token = jwt_for(args.jwt_key)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.run_id = args.run_id or (
            "artex-tor-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-" + secrets.token_hex(4)
        )
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", self.run_id):
            raise ValueError("run-id must contain only letters, numbers, underscores or hyphens")
        self.report = {
            "run_id": self.run_id,
            "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope": "core-only" if args.core_only else "full",
            "callback_provider": args.callback_provider,
            "callback_host": args.callback_host,
            "checks": [],
            "requests": [],
            "callback_events": [],
            "fail_closed_manifest": [],
            "network_uncertainties": [],
            "errors": [],
            "pool_restored": False,
            "probe_retry_policy": {
                "max_attempts": args.probe_attempts,
                "url": TOR_CHECK,
                "scope": "positive official curl_json/transparent GET network failures only",
                "route_changes": False,
                "callback_or_negative_retries": False,
            },
        }
        self.slots: list[dict] = []
        self.expected: list[str] = []
        self.blocked: list[str] = []
        self.callback_ipv4: str | None = None
        self.official_ipv4: str | None = None
        self.worker_proxy: str | None = None
        self.worker_ca: str | None = None
        if args.core_only:
            self.report["callback_verification"] = {
                "completed": False,
                "reason": "Core-only mode does not send callback requests or read callback logs.",
            }

    def check(self, name: str, passed: bool, detail=None) -> bool:
        item = {"name": name, "passed": bool(passed)}
        if detail is not None:
            item["detail"] = detail
        self.report["checks"].append(item)
        print(f"[{'PASS' if passed else 'FAIL'}] {name}", flush=True)
        return bool(passed)

    def api(self, path: str, method="GET", timeout=45, body=None) -> dict:
        request = urllib.request.Request(
            self.args.base_url.rstrip("/") + path,
            data=json.dumps(body if body is not None else {}).encode() if method == "POST" else None,
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json"},
            method=method,
        )
        try:
            with self.http.open(request, timeout=timeout) as response:
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        result = json.loads(body)
        if status >= 400:
            raise RuntimeError(f"API {method} {path} returned HTTP {status}: {result}")
        return result

    def container(self, command: list[str], timeout=None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", "exec", "-T", "artex", *command],
            cwd=self.args.project_dir,
            capture_output=True,
            text=True,
            timeout=timeout or self.args.timeout + 15,
            check=False,
        )

    def curl(self, url: str, proxy: str | None = None, marker: str | None = None,
             timeout: int | None = None, resolve: str | None = None) -> subprocess.CompletedProcess:
        limit = timeout or self.args.timeout
        command = ["curl", "--silent", "--show-error", "--fail",
                   "--connect-timeout", str(min(15, limit)), "--max-time", str(limit)]
        if proxy:
            command += ["--noproxy", "", "--proxy", proxy]
            if proxy == self.worker_proxy and self.worker_ca:
                command += ["--cacert", self.worker_ca]
        else:
            command += ["--noproxy", "*"]
        if marker:
            command += ["--header", "X-Artex-Tor-Test: " + marker]
        if resolve:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            command += ["--resolve", f"{parsed.hostname}:{port}:{resolve}"]
        command.append(url)
        return self.container(command, timeout=limit + 15)

    def curl_json(self, url: str, proxy: str) -> dict:
        attempts = self.args.probe_attempts if url == TOR_CHECK else 1
        for attempt in range(1, attempts + 1):
            result = self.curl(url, proxy=proxy)
            if result.returncode == 0:
                # Invalid JSON and an observed non-Tor exit are semantic
                # failures, not transient network failures to retry.
                return json.loads(result.stdout)
            self.report["network_uncertainties"].append({
                "url": url, "client": "curl", "route": safe_proxy(proxy),
                "attempt": attempt, "max_attempts": attempts,
                "exit_code": result.returncode, "stderr": result.stderr[-600:],
            })
            if result.returncode not in CURL_NETWORK_FAILURES or attempt == attempts:
                raise RuntimeError(f"curl failed ({result.returncode}) for {url} "
                                   f"on attempt {attempt}/{attempts}: {result.stderr[-600:]}")
            print(f"[INFO] Official curl probe network failure on attempt {attempt}/{attempts}; "
                  "retrying the same proxy route", flush=True)

    def resolve_ipv4(self, url: str, report_key: str, check_name: str) -> str | None:
        # Container DNS is already redirected to Tor here. Saving a destination
        # address lets the stopped-pool test exercise TCP without depending on DNS.
        parsed = urllib.parse.urlsplit(url)
        code = (
            "import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in "
            "socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),socket.AF_INET,socket.SOCK_STREAM)})))"
        )
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        result = self.container(["python3", "-c", code, parsed.hostname, str(port)], timeout=25)
        addresses = []
        if result.returncode == 0:
            addresses = [address for address in json.loads(result.stdout)
                         if ipaddress.ip_address(address).is_global]
        self.report[report_key] = addresses
        if self.check(check_name, bool(addresses),
                      {"addresses": addresses, "stderr": result.stderr[-600:]}):
            return addresses[0]
        return None

    def resolve_callback(self):
        self.callback_ipv4 = self.resolve_ipv4(
            f"http://{self.args.callback_host}", "callback_destination_ipv4",
            "resolve callback IPv4 for transport-only fail-closed test")

    def official_probe_once(self, client: str) -> subprocess.CompletedProcess:
        if client == "curl":
            return self.curl(TOR_CHECK)
        elif client == "python":
            code = """
import sys, urllib.error, urllib.request
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(sys.argv[1], timeout=int(sys.argv[2])) as response:
        print(response.read(65536).decode())
except urllib.error.HTTPError as error:
    print(str(error), file=sys.stderr)
    sys.exit(22)
except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
"""
            return self.container(["python3", "-c", code, TOR_CHECK, str(self.args.timeout)])
        elif client == "node":
            code = """
const https = require('node:https');
const req = https.get(process.argv[1], res => {
  let body = '';
  res.setEncoding('utf8');
  res.on('data', chunk => { body += chunk; });
  res.on('error', error => { console.error(error.message); process.exitCode = 1; });
  res.on('end', () => { console.log(body); if (res.statusCode !== 200) process.exitCode = 22; });
});
const timer = setTimeout(() => req.destroy(new Error('request timeout')), Number(process.argv[2]) * 1000);
timer.unref();
req.on('error', error => { console.error(error.message); process.exitCode = 1; clearTimeout(timer); });
req.on('close', () => clearTimeout(timer));
"""
            return self.container(["node", "-e", code, TOR_CHECK, str(self.args.timeout)])
        else:
            raise ValueError(client)

    def official_probe(self, client: str):
        attempts = self.args.probe_attempts
        for attempt in range(1, attempts + 1):
            result = self.official_probe_once(client)
            probe = {}
            parse_error = None
            if result.returncode == 0:
                try:
                    probe = json.loads(result.stdout)
                    if not isinstance(probe, dict):
                        raise ValueError("official check did not return an object")
                except ValueError as error:
                    probe, parse_error = {}, str(error)
            record = {
                "url": TOR_CHECK, "client": client, "route": "transparent",
                "attempt": attempt, "max_attempts": attempts,
                "exit_code": result.returncode, "stderr": result.stderr[-600:], "probe": probe,
            }
            if parse_error:
                record["parse_error"] = parse_error
            self.report["requests"].append(record)
            self.report.setdefault("transparent_probes", {})[client] = probe
            if result.returncode or parse_error:
                self.report["network_uncertainties"].append(record)
            network_failure = (result.returncode in CURL_NETWORK_FAILURES if client == "curl"
                               else result.returncode == 1)
            if network_failure and attempt < attempts:
                print(f"[INFO] Official {client} probe network failure on attempt {attempt}/{attempts}; "
                      "retrying the same transparent Tor route", flush=True)
                continue
            self.check(f"transparent {client} official Tor check",
                       result.returncode == 0 and probe.get("IsTor") is True, record)
            return

    def wait_for_pool(self, timeout: int) -> dict:
        deadline = time.monotonic() + timeout
        last = {}
        while True:
            last = self.api("/api/system/torpool")
            status = last.get("status") or {}
            instances = status.get("instances") or []
            if (last.get("enabled") and status.get("started") and instances
                    and all(i.get("running") and i.get("cookie_ready") for i in instances)):
                return status
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Tor pool was not ready within {timeout}s: {last}")
            time.sleep(2)

    @staticmethod
    def slot_proxy(slot: dict) -> str:
        return "socks5h://" + slot["socks_addr"]

    def worker_probe(self) -> bool:
        app = self.api(f"/api/agents/{self.args.agent}/egress/test", "POST", timeout=60)
        resolved = app.get("resolved") or {}
        proxy = resolved.get("proxy_url", "")
        parsed = urllib.parse.urlsplit(proxy)
        valid_proxy = parsed.scheme in {"http", "https", "socks5", "socks5h"} and bool(parsed.hostname)
        if valid_proxy:
            self.worker_proxy = proxy
            self.worker_ca = resolved.get("ca_cert") or None
        self.report["application_probe"] = {
            **app, "resolved": {**resolved, "proxy_url": safe_proxy(proxy) if proxy else ""},
        }
        return self.check(
            "application worker official Tor check",
            app.get("ok") is True and app.get("probe", {}).get("is_tor") is True
            and tor_plan(resolved) and valid_proxy,
            self.report["application_probe"],
        )

    def callback(self, label: str, proxy: str | None, scheme="https", client="curl"):
        marker = self.run_id + "/" + label
        url = f"{scheme}://{self.args.callback_host}/{marker}"
        if client == "curl":
            result = self.curl(url, proxy=proxy, marker=marker)
        elif client == "python":
            code = (
                "import sys,urllib.request; "
                "o=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
                "r=urllib.request.Request(sys.argv[1],headers={'X-Artex-Tor-Test':sys.argv[2]}); "
                "s=o.open(r,timeout=int(sys.argv[3])); print(s.status); s.read(4096)"
            )
            result = self.container(["python3", "-c", code, url, marker, str(self.args.timeout)])
        elif client == "node":
            code = """
const https = require('node:https');
const req = https.get(process.argv[1], {headers: {'X-Artex-Tor-Test': process.argv[2]}}, res => {
  res.resume();
  res.on('end', () => { console.log(res.statusCode); if (res.statusCode >= 400) process.exitCode = 1; });
});
const timer = setTimeout(() => req.destroy(new Error('request timeout')), Number(process.argv[3]) * 1000);
timer.unref();
req.on('error', error => { console.error(error.message); process.exitCode = 1; clearTimeout(timer); });
req.on('close', () => clearTimeout(timer));
"""
            result = self.container(["node", "-e", code, url, marker, str(self.args.timeout)])
        else:
            raise ValueError(client)
        self.report["requests"].append({
            "marker": marker, "client": client, "scheme": scheme,
            "route": safe_proxy(proxy) if proxy else "transparent",
            "exit_code": result.returncode, "stderr": result.stderr[-600:],
        })
        self.expected.append(marker)
        if result.returncode:
            self.report["network_uncertainties"].append({
                "marker": marker, "client": client, "exit_code": result.returncode,
                "stderr": result.stderr[-600:],
            })
        self.check("callback " + label, result.returncode == 0)

    def http_tool(self, label: str, proxy: str | None, blocked=False,
                  url: str | None = None, verify_tor=False) -> dict:
        marker = self.run_id + "/" + label
        limit = 12 if blocked else self.args.timeout
        callback_request = url is None
        spec = {
            "method": "GET", "url": url or f"https://{self.args.callback_host}/{marker}",
            "headers": {"X-Artex-Tor-Test": marker}, "timeout_ms": limit * 1000,
        }
        if proxy:
            spec["proxy"] = proxy
        if callback_request:
            (self.blocked if blocked else self.expected).append(marker)
        response = self.api("/api/tools/custom/test", "POST", timeout=limit + 15,
                            body={"kind": "http", "exec": spec})
        record = {
            "marker": marker, "url": spec["url"],
            "client": "application-go-http-tool", "scheme": "https",
            "route": safe_proxy(proxy) if proxy else "application-default",
            "is_error": response.get("is_error"), "output": str(response.get("output", ""))[-800:],
        }
        self.report["requests"].append(record)
        if blocked:
            self.report["fail_closed_manifest"].append(record)
            # Rejecting an invalid or foreign proxy configuration proves
            # neither Tor availability nor the application's fail-closed path.
            output = str(response.get("output", ""))
            configuration_refusal = any(message in output for message in [
                "不能覆盖统一出口", "出口上下文已失效", "不能借用其他任务", "代理地址无效",
            ])
            self.check("stopped-pool application HTTP tool refuses " + label,
                       response.get("is_error") is True and not configuration_refusal, record)
        else:
            passed = response.get("is_error") is False
            if verify_tor:
                try:
                    tool_result = json.loads(response.get("output", ""))
                    probe = json.loads(tool_result["body"])
                    record["probe"] = probe
                    passed = passed and tool_result.get("status") == 200 and probe.get("IsTor") is True
                except (ValueError, TypeError, KeyError, AttributeError) as error:
                    record["parse_error"] = str(error)
                    passed = False
            self.check("application HTTP tool " + label, passed, record)
            if not passed:
                self.report["network_uncertainties"].append(record)
        return response

    def read_events(self) -> list[dict]:
        payload = self.curl_json(self.args.callback_api, self.slot_proxy(self.slots[0]))
        return [row for row in callback_events(payload, self.args.callback_provider)
                if self.run_id in row.get("dump", "")]

    @staticmethod
    def has_marker(event: dict, marker: str) -> bool:
        # A marker ending in "-http" must not match the "-https" request.
        return bool(re.search(re.escape(marker) + r"(?=[/?\s]|$)", event.get("dump", "")))

    def verify_events(self):
        observation_start = time.monotonic()
        minimum_end = observation_start + self.args.negative_observation
        deadline = observation_start + max(self.args.log_wait, self.args.negative_observation)
        events = []
        seen = set()
        last_success = None
        missing = list(self.expected)
        while True:
            try:
                for event in self.read_events():
                    fingerprint = tuple(str(event.get(key, "")) for key in ["protocol", "ip", "timestamp", "dump"])
                    if fingerprint not in seen:
                        seen.add(fingerprint)
                        events.append(event)
                last_success = time.monotonic()
            except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                self.report["network_uncertainties"].append({
                    "phase": "callback-log-observation", "error": str(error),
                })
                print("[INFO] Callback log read failed; absence is not yet verified", flush=True)
            missing = [marker for marker in self.expected
                       if not any(self.has_marker(event, marker) for event in events)]
            now = time.monotonic()
            if ((not missing and last_success is not None and last_success >= minimum_end)
                    or now >= deadline):
                break
            time.sleep(3)
        observed_seconds = (last_success - observation_start) if last_success is not None else 0
        observation_complete = observed_seconds >= self.args.negative_observation
        self.report["negative_observation_seconds"] = round(observed_seconds, 2)
        self.check("HTTP logs remain observable for the negative observation window",
                   observation_complete,
                   {"required_seconds": self.args.negative_observation,
                    "observed_seconds": round(observed_seconds, 2)})
        self.report["callback_events"] = events
        self.check("all successful-route markers appear in HTTP callback logs", not missing, missing)
        forbidden = [event for event in events
                     if any(self.has_marker(event, marker) for marker in self.blocked)]
        self.check("no callback from stopped-pool attempts", observation_complete and not forbidden,
                   {"observation_complete": observation_complete, "unexpected_events": forbidden})

        result = self.curl(TOR_EXITS, self.slot_proxy(self.slots[0]))
        if result.returncode:
            raise RuntimeError(f"Cannot read Tor exit list: {result.stderr[-600:]}")
        exits = set()
        for line in result.stdout.splitlines():
            try:
                exits.add(str(ipaddress.ip_address(line.strip())))
            except ValueError:
                continue
        if not exits:
            raise RuntimeError("Tor bulk exit list contained no IP addresses")
        observed = sorted({str(event.get("ip", "")) for event in events})
        unknown = []
        for address in observed:
            try:
                if str(ipaddress.ip_address(address)) not in exits:
                    unknown.append(address)
            except ValueError:
                unknown.append(address)
        self.report["observed_http_ips"] = observed
        self.report["tor_exit_list_size"] = len(exits)
        self.report["tor_exit_list_url"] = TOR_EXITS
        self.check("every observed HTTP source IP is a Tor exit", bool(observed) and not unknown, unknown)

    def fail_closed(self):
        core_only = self.args.core_only
        destination_ipv4 = self.official_ipv4 if core_only else self.callback_ipv4
        if core_only and not destination_ipv4:
            raise RuntimeError("Official check IPv4 must be resolved before stopping the pool")
        stop_attempted = False
        try:
            stop_attempted = True
            stopped = self.api("/api/system/torpool/stop", "POST", timeout=60)
            self.report["pool_stopped_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            if not self.check("pool stops", not stopped.get("status", {}).get("started")):
                raise RuntimeError("Pool stop was not confirmed")
            # No retries: the same known-working target must become unreachable.
            attempts = [("blocked-transparent", None, None),
                        ("blocked-socks", self.slot_proxy(self.slots[0]), None)]
            if destination_ipv4:
                attempts.append(("blocked-transparent-pinned-ip", None, destination_ipv4))
            for label, proxy, destination in attempts:
                marker = self.run_id + "/" + label
                if not core_only:
                    self.blocked.append(marker)
                target = TOR_CHECK if core_only else f"http://{self.args.callback_host}/{marker}"
                result = self.curl(target, proxy,
                                   marker=marker, timeout=12, resolve=destination)
                # Docker/tool errors and HTTP errors are not proof of a closed path.
                network_failures = {5, 6, 7, 28, 35, 52, 55, 56, 97}
                record = {
                    "marker": marker, "url": target, "client": "curl",
                    "scheme": urllib.parse.urlsplit(target).scheme,
                    "route": safe_proxy(proxy) if proxy else "transparent",
                    "pinned_destination_ipv4": destination, "exit_code": result.returncode,
                    "stderr": result.stderr[-600:],
                }
                self.report["fail_closed_manifest"].append(record)
                self.check(label + " refuses outbound request", result.returncode in network_failures, record)
            # Custom-tool API calls have no worker Agent context. Let the
            # application create its own registered routing context instead of
            # borrowing a worker token or bypassing routing with a slot SOCKS URL.
            self.http_tool("blocked-application-http-tool", None, blocked=True,
                           url=TOR_CHECK if core_only else None)
            response = self.api(f"/api/agents/{self.args.agent}/egress/test", "POST", timeout=45)
            probe = response.get("probe") or {}
            error = response.get("error") or probe.get("error", "")
            resolved = response.get("resolved") or {}
            # A routed CONNECT can report 502/Bad Gateway after the physical
            # Tor resolver refuses it. The successful pre-stop probe and the
            # retained Tor provider establish which route actually failed.
            refused_route = tor_plan(resolved) or any(word in error for word in [
                "不会回退直连", "拒绝", "fail-closed",
            ])
            reported = {
                **response,
                "resolved": {**resolved, "proxy_url": safe_proxy(resolved["proxy_url"])
                             if resolved.get("proxy_url") else ""},
            }
            self.check("application refuses egress when pool is stopped",
                       response.get("ok") is False and bool(error) and not probe.get("ip")
                       and refused_route,
                       reported)
        finally:
            if stop_attempted:
                print("[INFO] Restoring Tor pool", flush=True)
                try:
                    self.api("/api/system/torpool/start", "POST", timeout=240)
                    self.wait_for_pool(self.args.ready_timeout)
                    self.report["pool_restored"] = True
                    self.report["pool_restored_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                    self.check("Tor pool restored after fail-closed test", True)
                except Exception as error:
                    self.report["errors"].append("Pool restoration failed: " + str(error))
                    self.check("Tor pool restored after fail-closed test", False, str(error))

    def run_core(self):
        print("[INFO] Core-only scope: callback verification remains incomplete", flush=True)
        for client in ["curl", "python", "node"]:
            self.official_probe(client)
        self.worker_probe()
        self.http_tool("official-check-routing", None, url=TOR_CHECK, verify_tor=True)
        self.official_ipv4 = self.resolve_ipv4(
            TOR_CHECK, "official_destination_ipv4",
            "resolve official check IPv4 for transport-only fail-closed test")
        if not self.official_ipv4:
            raise RuntimeError("Cannot perform pinned-IP fail-closed test without official check IPv4")
        self.fail_closed()

    def run(self):
        print("[INFO] Run " + self.run_id, flush=True)
        status = self.wait_for_pool(self.args.ready_timeout)
        self.slots = sorted(status["instances"], key=lambda slot: slot["id"])
        self.report["pool_before"] = status
        if not self.check("configured number of Tor slots", len(self.slots) == self.args.expected_slots,
                          {"expected": self.args.expected_slots, "actual": len(self.slots)}):
            raise RuntimeError("Unexpected pool size; refusing an incomplete pool verification")
        verified = []
        for slot in self.slots:
            probe = self.curl_json(TOR_CHECK, self.slot_proxy(slot))
            self.report.setdefault("slot_probes", []).append({"slot": slot["id"], **probe})
            if self.check(f"slot {slot['id']} official Tor check", probe.get("IsTor") is True, probe):
                verified.append(slot)
        if len(verified) != len(self.slots):
            raise RuntimeError("A slot failed the official Tor check; callbacks were not sent")

        if self.args.core_only:
            self.run_core()
            return

        # Validate this instance and obtain a clean per-run baseline before callbacks.
        self.report["baseline_matching_events"] = len(self.read_events())
        self.resolve_callback()
        for slot in self.slots:
            for scheme in ["http", "https"]:
                self.callback(f"slot-{slot['id']}-{scheme}", self.slot_proxy(slot), scheme=scheme)

        transparent = self.curl(TOR_CHECK)
        transparent_probe = json.loads(transparent.stdout) if transparent.returncode == 0 else {}
        self.report["transparent_probe"] = transparent_probe
        if self.check("transparent curl official Tor check", transparent_probe.get("IsTor") is True):
            self.callback("transparent-curl-http", None, scheme="http")
            self.callback("transparent-python-https", None, client="python")
            self.callback("transparent-node-https", None, client="node")
            self.http_tool("application-transparent-http-tool", None)
        elif transparent.returncode:
            self.report["network_uncertainties"].append({
                "phase": "transparent-official-check", "exit_code": transparent.returncode,
                "stderr": transparent.stderr[-600:],
            })

        if self.worker_probe():
            self.callback("application-worker-route", self.worker_proxy)
            self.http_tool("application-http-tool", None)

        self.fail_closed()
        if self.report["pool_restored"]:
            self.verify_events()

    def save(self):
        self.report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        passed = (bool(self.report["checks"]) and not self.report["errors"]
                  and all(item["passed"] for item in self.report["checks"]))
        if self.args.core_only:
            self.report["core_ok"] = passed
            self.report["ok"] = False  # Full verification requires callback evidence.
            print(f"[INFO] Core checks {'passed' if passed else 'failed'}; "
                  "callback verification incomplete", flush=True)
        else:
            self.report["ok"] = passed
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(self.report, ensure_ascii=False, indent=2) + "\n")
        print(f"[INFO] Report: {self.args.output}", flush=True)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project-dir", type=Path, default=root)
    parser.add_argument("--base-url", default="http://127.0.0.1:8787")
    parser.add_argument("--jwt-key", type=Path, default=root / "jwt.key")
    parser.add_argument("--agent", default="worker")
    parser.add_argument("--expected-slots", type=int, default=5)
    parser.add_argument("--core-only", action="store_true",
                        help="verify official Tor routing and fail-closed behavior without callbacks")
    parser.add_argument("--callback-provider", choices=["cvss", "webhook-site"], default="cvss")
    parser.add_argument("--callback-token", help="existing Webhook.site token UUID; never creates a token")
    parser.add_argument("--callback-host", help="override the selected provider's HTTP callback host")
    parser.add_argument("--callback-api", help="override the selected provider's request-log API URL")
    parser.add_argument("--run-id")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--probe-attempts", type=int, choices=range(1, 6), default=1,
                        help="maximum attempts for positive official GET network failures on the same route (1-5)")
    parser.add_argument("--ready-timeout", type=int, default=240)
    parser.add_argument("--log-wait", type=int, default=90)
    parser.add_argument("--negative-observation", type=int, default=20,
                        help="minimum callback-log observation window after pool recovery (at least 15s)")
    parser.add_argument("--output", type=Path, default=Path("/tmp/artex-docker-tor-check.json"))
    args = parser.parse_args()
    if args.negative_observation < 15:
        parser.error("--negative-observation must be at least 15 seconds")
    if args.callback_provider == "webhook-site":
        if not args.callback_token or not re.fullmatch(
                r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", args.callback_token):
            parser.error("--callback-provider webhook-site requires --callback-token UUID")
        token = args.callback_token.lower()
        args.callback_host = args.callback_host or f"{token}.webhook.site"
        args.callback_api = args.callback_api or (
            f"https://webhook.site/token/{token}/requests?sorting=newest&per_page=100")
    else:
        if args.callback_token:
            parser.error("--callback-token is only supported by --callback-provider webhook-site")
        if not args.core_only and (not args.callback_host or not args.callback_api):
            parser.error("CVSS callback verification requires your own --callback-host and --callback-api; "
                         "or use --callback-provider webhook-site --callback-token UUID")
    return args


def main() -> int:
    args = parse_args()
    try:
        verification = Verification(args)
    except Exception as error:
        print(f"[FAIL] Cannot initialize verification: {error}", file=sys.stderr)
        return 1

    def terminate(_signum, _frame):
        raise KeyboardInterrupt("verification interrupted")

    signal.signal(signal.SIGTERM, terminate)
    try:
        verification.run()
    except (Exception, KeyboardInterrupt) as error:
        verification.report["errors"].append(f"{type(error).__name__}: {error}")
        print(f"[FAIL] {error}", file=sys.stderr, flush=True)
    finally:
        verification.save()
    result_key = "core_ok" if args.core_only else "ok"
    return 0 if verification.report[result_key] else 1


if __name__ == "__main__":
    sys.exit(main())
