#!/usr/bin/env python3
"""Live Docker Tor/Clash routing regression, using only host Python stdlib.

Run after rebuilding the application and enabling a real Clash node:
    python3 test/regression/docker_egress_routing_check.py --output /tmp/egress.json

This intentionally interrupts both proxy services. Run on an idle local stack.
The existing JWT key is read locally; neither it, the JWT, context proxy tokens,
nor upstream credentials are included in output. Rules and capture settings are
temporarily replaced, then restored. A temporary Agent and (when no LLM is
configured) paused task are removed in finally. With an LLM configured, supply
--task-id for an existing paused/finished task; its egress is restored instead.

The official Tor endpoint reports the HTTP request's source IP. Audit IPs are
separate same-provider probes and are reported with that limitation. POST replay
is covered by egressroute's local fault-injection tests, not by this script.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
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

from docker_tor_check import jwt_for, safe_proxy


TOR_CHECK = "https://check.torproject.org/api/ip"
ROUTING = "/api/system/egress-routing"
CREDENTIAL_URL = re.compile(r"(?i)(https?|socks5h?)://[^\s/@]+@")


def scrub(value):
    """Do not persist opaque context credentials or upstream credentials."""
    if isinstance(value, dict):
        return {key: (safe_proxy(item) if key in {"proxy_url", "proxy", "egress_proxy"}
                      and isinstance(item, str) and item else scrub(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str):
        return CREDENTIAL_URL.sub(r"\1://***@", value)
    return value


def http_tool_observation(output):
    """Unwrap runHTTPTool's JSON envelope before parsing its string body."""
    try:
        payload = json.loads(output)
    except (TypeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        body = payload.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                body = None
        if isinstance(body, dict) and "IP" in body and "IsTor" in body:
            return body
        if "IP" in payload and "IsTor" in payload:
            return payload
    # Keep compatibility with older tools that prepend response headers.
    for offset, character in enumerate(output):
        if character != "{":
            continue
        try:
            candidate, _ = json.JSONDecoder().raw_decode(output[offset:])
        except ValueError:
            continue
        if isinstance(candidate, dict) and "IP" in candidate and "IsTor" in candidate:
            return candidate
    return None


class Verification:
    def __init__(self, args):
        self.args = args
        self.token = jwt_for(args.jwt_key)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.run_id = "egress_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S_") + secrets.token_hex(3)
        self.agent_key = self.run_id
        self.task_id = None
        self.created_agent = False
        self.created_task = False
        self.original_task = None
        self.original_config = None
        self.original_capture = None
        self.original_active = None
        self.restore_tor = False
        self.restore_clash = False
        self.clash_backup_dir = None
        self.report = {
            "run_id": self.run_id, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target": TOR_CHECK, "checks": [], "probes": [], "errors": [],
            "restoration": {}, "fault_tests": not args.skip_failures,
            "limitations": [
                "Exit IP is the official Tor check endpoint's HTTP-observed source IP.",
                "Audit exit IPs are cached same-provider probes, not packet-level target receipts.",
                "POST non-replay is covered by local egressroute fault-injection tests.",
            ],
        }

    def check(self, name, passed, detail=None):
        record = {"name": name, "passed": bool(passed)}
        if detail is not None:
            record["detail"] = scrub(detail)
        self.report["checks"].append(record)
        print(f"[{'PASS' if passed else 'FAIL'}] {name}", flush=True)
        return bool(passed)

    def api(self, path, method="GET", body=None, timeout=55):
        request = urllib.request.Request(
            self.args.base_url.rstrip("/") + path,
            data=json.dumps(body if body is not None else {}).encode() if method in {"POST", "PUT", "PATCH"} else None,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
            method=method,
        )
        try:
            with self.http.open(request, timeout=timeout) as response:
                status, payload = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, payload = error.code, error.read()
        result = json.loads(payload)
        if status >= 400:
            raise RuntimeError(f"API {method} {path}: HTTP {status}: {scrub(result)}")
        return result

    def container(self, command, timeout=60):
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "artex", *command],
            cwd=self.args.project_dir, capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"Container operation failed ({result.returncode}): " + scrub(result.stderr[-600:]))
        return result

    def configure(self, provider=None, allow_fallback=False, enabled=False, threshold=2, cooldown=12):
        cfg = copy.deepcopy(self.original_config)
        cfg["rules"] = [] if provider is None else [{
            "id": self.run_id + "_target", "type": "domain", "value": "check.torproject.org",
            "provider": provider, "allow_fallback": allow_fallback, "enabled": True,
        }]
        cfg["fallback"] = {"enabled": enabled, "failure_threshold": threshold, "cooldown_seconds": cooldown}
        result = self.api(ROUTING, "PUT", {"config": cfg})
        if result.get("config") != cfg:
            raise RuntimeError("Saved routing configuration differs from requested configuration")
        return cfg

    def set_capture(self, enabled):
        self.api("/api/settings", "PUT", {"traffic_capture": enabled})
        if self.api("/api/settings").get("traffic_capture") is not enabled:
            raise RuntimeError("Capture setting did not persist")

    def set_task(self, mode):
        self.api(f"/api/tasks/{self.task_id}/egress", "PUT", {"mode": mode, "proxy": ""})

    def set_agent(self, mode):
        self.api(f"/api/agents/{self.agent_key}/config", "PUT", {"egress_mode": mode})

    def probe(self, label, expected_provider, expected_tor, *, mode="inherit", task=False,
              agent=False, blocked=False, attempts=1):
        body = {"url": TOR_CHECK, "mode": mode}
        if task:
            body["task_id"] = self.task_id
        if agent:
            body["agent_key"] = self.agent_key
        response = {}
        for attempt in range(attempts):
            response = self.api(ROUTING + "/test", "POST", body)
            self.report["probes"].append({"label": label, "attempt": attempt + 1, **scrub(response)})
            if blocked or response.get("ok") or attempt == attempts - 1:
                break
            time.sleep(2)
        plan, observed = response.get("resolved") or {}, response.get("probe") or {}
        if blocked:
            error = observed.get("error") or response.get("error")
            passed = response.get("ok") is False and bool(error) and not observed.get("ip")
            if plan:
                passed = passed and plan.get("provider") == expected_provider
        else:
            try:
                valid_ip = ipaddress.ip_address(observed.get("ip", "")).is_global
            except ValueError:
                valid_ip = False
            passed = (response.get("ok") is True and plan.get("provider") == expected_provider
                      and observed.get("is_tor") is expected_tor and valid_ip)
        self.check(label, passed, response)
        return response

    def http_tool(self, label, expected_tor, *, blocked=False):
        response = self.api("/api/tools/custom/test", "POST", {
            "kind": "http", "exec": {"method": "GET", "url": TOR_CHECK, "timeout_ms": 35000},
        })
        output = str(response.get("output", ""))
        observed = http_tool_observation(output)
        if blocked:
            passed = response.get("is_error") is True and observed is None
        else:
            passed = response.get("is_error") is False and observed is not None and observed.get("IsTor") is expected_tor
        self.check(label, passed, {"result": response, "observed": observed})
        return observed

    def wait_status(self, provider, ready=True, timeout=240):
        deadline = time.monotonic() + timeout
        while True:
            status = self.api(ROUTING + "/status").get("status") or {}
            if (status.get(provider) or {}).get("ready") is ready:
                return status
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{provider} readiness did not become {ready} within {timeout}s")
            time.sleep(2)

    def stop_tor(self):
        self.restore_tor = True
        response = self.api("/api/system/torpool/stop", "POST", timeout=90)
        if (response.get("status") or {}).get("started"):
            raise RuntimeError("Tor pool stop was not confirmed")

    def start_tor(self):
        self.api("/api/system/torpool/start", "POST", timeout=300)
        self.wait_status("tor", timeout=self.args.ready_timeout)
        self.restore_tor = False

    def stop_clash(self):
        self.restore_clash = True
        # Match the dedicated executable name; do not read node/controller files.
        code = """from pathlib import Path
import os, signal, time
processes = []
for path in Path('/proc').glob('[0-9]*'):
    try:
        if (path / 'comm').read_text().strip() == 'mihomo':
            processes.append(int(path.name))
    except (OSError, ValueError):
        pass
if not processes:
    raise SystemExit('Clash was not running before fault injection')
for pid in processes:
    os.kill(pid, signal.SIGTERM)
for _ in range(50):
    alive = []
    for pid in processes:
        try:
            if Path(f'/proc/{pid}/comm').read_text().strip() == 'mihomo':
                alive.append(pid)
        except OSError:
            pass
    if not alive:
        break
    time.sleep(.1)
else:
    raise SystemExit('Clash did not stop')
print('Clash stopped')
"""
        self.container(["/usr/bin/python3", "-c", code])
        self.wait_status("clash", ready=False, timeout=20)

    def start_clash(self):
        self.container(["/usr/local/bin/artex-clash-restart.sh"], timeout=75)
        self.wait_status("clash", timeout=30)
        self.restore_clash = False

    def restore_clash_snapshot(self):
        if self.clash_backup_dir is None:
            return
        code = """from pathlib import Path
import hashlib, json, os, stat, sys, tempfile
backup = Path(sys.argv[1])
manifest = backup / 'manifest.json'
if manifest.is_file():
    saved = json.loads(manifest.read_text())
    directory = Path(os.environ.get('ARTEX_CLASH_DIR', '/var/lib/artex-clash'))
    if saved['directory'] != str(directory):
        raise SystemExit('Clash backup directory mismatch')
    for name in ('nodes.yaml', 'config.yaml'):
        item = saved['files'][name]
        data = (backup / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise SystemExit('Clash backup integrity verification failed')
        fd, temporary = tempfile.mkstemp(prefix='.egress-restore-', dir=directory)
        try:
            with os.fdopen(fd, 'wb') as output:
                os.fchmod(output.fileno(), item['mode'])
                os.fchown(output.fileno(), item['uid'], item['gid'])
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, directory / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
print('Clash files restored; credentials remain inside container')
"""
        self.container(["/usr/bin/python3", "-c", code, self.clash_backup_dir])
        # Restart must use the restored normal environment and concrete nodes.
        self.start_clash()
        verify = """from pathlib import Path
import hashlib, json, shutil, sys
backup = Path(sys.argv[1])
manifest = backup / 'manifest.json'
if manifest.is_file():
    saved = json.loads(manifest.read_text())
    directory = Path(saved['directory'])
    if not all(hashlib.sha256((directory / name).read_bytes()).hexdigest() == item['sha256']
               for name, item in saved['files'].items()):
        raise SystemExit('Restored Clash files differ from original backup; private backup retained')
if backup.exists():
    shutil.rmtree(backup)
print('Clash backup verified and removed')
"""
        self.container(["/usr/bin/python3", "-c", verify, self.clash_backup_dir])
        self.clash_backup_dir = None
        self.report["restoration"]["empty_node_clash_files_and_service"] = True

    def empty_node_check(self):
        """Exercise both app refusal and the real reject-only Mihomo listener."""
        self.clash_backup_dir = "/tmp/artex-clash-verify-" + self.run_id
        self.restore_clash = True
        setup = """from pathlib import Path
import hashlib, json, os, stat, sys, tempfile
backup = Path(sys.argv[1])
backup.mkdir(mode=0o700)
directory = Path(os.environ.get('ARTEX_CLASH_DIR', '/var/lib/artex-clash'))
saved = {'directory': str(directory), 'files': {}}
for name in ('nodes.yaml', 'config.yaml'):
    source = directory / name
    info = source.stat()
    if source.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise SystemExit('Clash file is not a regular private file')
    data = source.read_bytes()
    fd = os.open(backup / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    saved['files'][name] = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid,
                           'gid': info.st_gid, 'sha256': hashlib.sha256(data).hexdigest()}
# The complete manifest is written before the first mutation. If preparation
# fails before this point, restoring the service is safe without changing files.
fd = os.open(backup / 'manifest.partial', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    json.dump(saved, output)
    output.flush()
    os.fsync(output.fileno())
os.replace(backup / 'manifest.partial', backup / 'manifest.json')
fd, temporary = tempfile.mkstemp(prefix='.egress-empty-', dir=directory)
try:
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(b'proxies: []\\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, directory / 'nodes.yaml')
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print('Private Clash backup prepared and empty nodes installed')
"""
        try:
            self.container(["/usr/bin/python3", "-c", setup, self.clash_backup_dir])
            self.container(["env", "ARTEX_CLASH_UPSTREAM=", "ARTEX_CLASH_LEGACY_CONFIG=/nonexistent-artex-verification",
                            "/usr/local/bin/artex-clash-restart.sh"], timeout=75)
            self.wait_status("clash", ready=False, timeout=20)
            inspect = """from pathlib import Path
import json, os, socket, stat, subprocess, yaml
directory = Path(os.environ.get('ARTEX_CLASH_DIR', '/var/lib/artex-clash'))
config = yaml.safe_load((directory / 'config.yaml').read_text())
nodes = yaml.safe_load((directory / 'nodes.yaml').read_text())
result = subprocess.run(['/usr/local/bin/artex-clash-config.py', 'status'],
                        capture_output=True, text=True, timeout=8, check=True)
status = json.loads(result.stdout)
with socket.create_connection(('127.0.0.1', 7890), timeout=2):
    listener_ready = True
print(json.dumps({'reject_only': config.get('rules') == ['MATCH,REJECT']
                  and config.get('proxies') == [] and config.get('proxy-groups') == [],
                  'empty_nodes': nodes.get('proxies') == [],
                  'private_files': all(stat.S_IMODE((directory / name).stat().st_mode) == 0o600
                                       for name in ('nodes.yaml', 'config.yaml')),
                  'listener_ready': listener_ready, 'status': status}))
"""
            inspected = json.loads(self.container(["/usr/bin/python3", "-c", inspect]).stdout)
            status = inspected.get("status") or {}
            self.check("empty-node Clash compiles MATCH,REJECT and reports not ready",
                       inspected.get("reject_only") is True and inspected.get("empty_nodes") is True
                       and inspected.get("private_files") is True and inspected.get("listener_ready") is True
                       and status.get("node_count") == 0
                       and status.get("ready") is False, inspected)
            self.probe("application rejects Clash with zero real nodes", "clash", False, mode="clash", blocked=True)
            direct = """import json, subprocess
result = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--noproxy', '',
                         '--proxy', 'http://127.0.0.1:7890', '--connect-timeout', '8',
                         '--max-time', '12', 'https://check.torproject.org/api/ip'],
                        capture_output=True, text=True, timeout=18, check=False)
print(json.dumps({'exit_code': result.returncode, 'response_bytes': len(result.stdout),
                  'stderr': result.stderr[-400:]}))
"""
            result = json.loads(self.container(["/usr/bin/python3", "-c", direct]).stdout)
            self.check("real empty-node Mihomo listener rejects target without DIRECT fallback",
                       result.get("exit_code") in {5, 6, 7, 22, 28, 35, 52, 55, 56, 97}, result)
            self.probe("default Tor remains available with empty-node Clash", "tor", True, attempts=2)
        finally:
            self.restore_clash_snapshot()
        self.probe("Clash real node restored after empty-node verification", "clash", False, mode="clash", attempts=2)

    def prepare_fixture(self):
        if self.args.task_id:
            selected = next((row for row in self.api("/api/tasks").get("tasks", [])
                             if str(row.get("id")) == self.args.task_id), None)
            if selected is None or selected.get("status") not in {"paused", "done", "failed", "created"} or selected.get("in_flight", 0):
                raise RuntimeError("--task-id must identify an idle paused/finished task")
            self.task_id, self.original_task = self.args.task_id, selected
        else:
            if self.api("/api/stats").get("llm_configured"):
                raise RuntimeError("LLM is configured; use --task-id with an idle task to avoid starting new work")
            self.original_active = self.api("/api/tasks").get("active")
            task = self.api("/api/tasks", "POST", {
                "name": self.run_id, "description": "Local egress regression fixture",
                "goal": "", "seed_first_intent": False, "coverage_enabled": False,
                "egress_mode": "inherit",
            })
            self.task_id, self.created_task = str(task["id"]), True
            paused = self.api("/api/tasks/control/batch", "POST", {"task_ids": [self.task_id], "action": "pause"})
            if not any(row.get("id") == self.task_id and row.get("ok") is True for row in paused.get("items", [])):
                raise RuntimeError("Temporary routing fixture could not be paused")
        self.api("/api/agents", "POST", {
            "key": self.agent_key, "name": "Local egress regression fixture", "egress_mode": "inherit",
        })
        self.created_agent = True

    def routing_checks(self):
        self.check("deployed initial configuration has automatic fallback off",
                   (self.original_config.get("fallback") or {}).get("enabled") is False)
        self.configure()
        self.set_capture(False)
        default = self.probe("default request uses Tor", "tor", True, attempts=3)
        clash = self.probe("explicit Clash uses a non-Tor proxy exit", "clash", False, mode="clash", attempts=2)
        self.check("Tor and Clash have distinct observed exit IPs",
                   bool((default.get("probe") or {}).get("ip"))
                   and (default.get("probe") or {}).get("ip") != (clash.get("probe") or {}).get("ip"))
        self.prepare_fixture()
        self.configure("clash")
        self.probe("domain rule selects Clash", "clash", False)
        self.probe("explicit Tor overrides Clash target rule", "tor", True, mode="tor", attempts=2)
        self.set_agent("tor")
        self.probe("Agent Tor overrides Clash target rule", "tor", True, agent=True, attempts=2)
        self.set_task("clash")
        self.probe("task Clash overrides Agent Tor", "clash", False, task=True, agent=True)
        self.set_agent("clash")
        self.set_task("tor")
        self.probe("task Tor overrides Agent Clash", "tor", True, task=True, agent=True, attempts=2)
        self.set_task("inherit")
        self.probe("switch task back to inheritance selects Agent Clash", "clash", False, task=True, agent=True)
        self.set_agent("inherit")
        self.http_tool("HTTP tool follows Clash target rule", False)
        command = self.api("/api/tools/custom/test", "POST", {
            "kind": "command", "exec": {"command": "printf artex_egress_command_should_be_refused", "timeout_ms": 3000},
        })
        self.check("unsupported command tool explicitly refuses controlled Clash policy",
                   command.get("is_error") is True and "artex_egress_command_should_be_refused" not in str(command.get("output", "")), command)
        self.set_capture(True)
        inherited = self.probe("recording proxy preserves target-rule Clash context", "clash", False)
        explicit = self.probe("recording proxy preserves explicit Tor context", "tor", True, mode="tor", attempts=2)
        inherited_port = urllib.parse.urlsplit((inherited.get("resolved") or {}).get("proxy_url", "")).port
        explicit_port = urllib.parse.urlsplit((explicit.get("resolved") or {}).get("proxy_url", "")).port
        self.check("both recording tests used the same recording listener",
                   inherited_port == self.args.recording_port and inherited_port == explicit_port,
                   {"inherited_port": inherited_port, "explicit_port": explicit_port})
        self.http_tool("HTTP tool keeps Clash route through recording proxy", False)
        self.set_capture(False)

    def fault_checks(self):
        self.configure("tor", allow_fallback=True, enabled=False)
        self.stop_tor()
        self.probe("Tor failure with automatic fallback off refuses target", "tor", True, blocked=True)
        self.http_tool("HTTP tool refuses Tor failure without direct retry", True, blocked=True)
        self.probe("Clash remains available while Tor is stopped", "clash", False, mode="clash")
        self.configure(enabled=True)
        self.probe("global fallback alone cannot relax unapproved default target", "tor", True, blocked=True)
        self.configure("tor", allow_fallback=True, enabled=True, threshold=2, cooldown=12)
        self.probe("first allowed-target failure remains refused below threshold", "tor", True, blocked=True)
        fallback = self.probe("failure threshold activates allowlisted Clash fallback", "clash", False)
        self.check("fallback selection records its reason",
                   (fallback.get("resolved") or {}).get("reason") == "tor-fallback-cooldown", fallback.get("resolved"))
        self.probe("explicit Tor remains strict even during allowed fallback", "tor", True, mode="tor", blocked=True)
        state = self.api(ROUTING + "/status").get("status", {}).get("fallback_states") or []
        self.check("fallback state exposes threshold and cooldown", any(
            row.get("host") == "check.torproject.org" and row.get("failures", 0) >= 2
            and row.get("fallback_until") for row in state), state)
        self.stop_clash()
        self.probe("explicit Clash fails closed when Clash is unavailable", "clash", False, mode="clash", blocked=True)
        self.probe("both failed exits refuse allowlisted target", "clash", False, blocked=True)
        self.start_clash()
        self.start_tor()
        # Tor bootstrap may already have consumed the short cooldown. The state
        # must still be allowed to expire naturally; do not reset configuration.
        time.sleep(13)
        self.probe("cooldown recovery returns allowed target to Tor", "tor", True, attempts=3)
        self.configure()
        self.stop_clash()
        self.probe("Clash failure does not affect default Tor", "tor", True, attempts=2)
        self.probe("Clash failure never silently switches explicit selection to Tor", "clash", False, mode="clash", blocked=True)
        self.start_clash()
        self.probe("Clash restarts using persisted real node", "clash", False, mode="clash", attempts=2)
        self.empty_node_check()

    def audit_checks(self):
        deadline = time.monotonic() + 100
        matching = []
        while True:
            events = self.api(ROUTING + "/audit").get("events") or []
            matching = [row for row in events if row.get("rule_id") == self.run_id + "_target"]
            if matching and any(row.get("exit_ip") for row in matching):
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(3)
        self.report["audit_sample"] = scrub(matching[:25])
        self.check("persistent audit includes provider, matched rule and reason", bool(matching)
                   and all(row.get("provider") in {"tor", "clash"} and row.get("reason") for row in matching))
        self.check("audit records an observed same-provider exit IP with provenance",
                   any(row.get("exit_ip") and row.get("exit_ip_source") == "same-provider-probe" for row in matching))

    def restore(self):
        operations = []
        if self.clash_backup_dir is not None:
            operations.append(("empty_node_clash_files_and_service", self.restore_clash_snapshot))
        elif self.restore_clash:
            operations.append(("clash_service", self.start_clash))
        if self.restore_tor:
            operations.append(("tor_pool", self.start_tor))
        if self.original_config is not None:
            operations.append(("routing_config", lambda: self.api(ROUTING, "PUT", {"config": self.original_config})))
        if self.original_capture is not None:
            operations.append(("traffic_capture", lambda: self.set_capture(self.original_capture)))
        if self.original_task is not None:
            operations.append(("task_egress", lambda: self.api(f"/api/tasks/{self.task_id}/egress", "PUT", {
                "mode": self.original_task.get("egress_mode") or "inherit", "proxy": self.original_task.get("egress_proxy") or "",
            })))
        if self.created_task:
            operations.append(("temporary_task_deleted", lambda: self.api(f"/api/tasks/{self.task_id}", "DELETE", timeout=90)))
            if self.original_active:
                operations.append(("original_active_task", lambda: self.api("/api/active", "POST", {"id": self.original_active})))
        if self.created_agent:
            operations.append(("temporary_agent_deleted", lambda: self.api(f"/api/agents/{self.agent_key}", "DELETE")))
        for name, operation in operations:
            try:
                operation()
                self.report["restoration"][name] = True
                print("[RESTORED] " + name, flush=True)
            except Exception as error:
                self.report["restoration"][name] = False
                self.report["errors"].append("Restoration " + name + ": " + scrub(str(error)))
                print("[RESTORE FAILED] " + name, flush=True)
        try:
            status = self.api(ROUTING + "/status").get("status") or {}
            self.report["final_status"] = scrub(status)
            self.check("Tor and Clash services are both ready after restoration",
                       (status.get("tor") or {}).get("ready") is True and (status.get("clash") or {}).get("ready") is True, status)
            if self.original_config is not None:
                self.check("original routing configuration restored exactly",
                           self.api(ROUTING).get("config") == self.original_config)
        except Exception as error:
            self.report["errors"].append("Final restoration verification: " + scrub(str(error)))

    def run(self):
        try:
            self.original_config = self.api(ROUTING)["config"]
            self.original_capture = self.api("/api/settings")["traffic_capture"]
            status = self.api(ROUTING + "/status").get("status") or {}
            self.report["initial_status"] = scrub(status)
            services_ready = (status.get("tor") or {}).get("ready") and (status.get("clash") or {}).get("ready")
            if not services_ready or (status.get("clash") or {}).get("node_count", 0) < 1:
                raise RuntimeError("Preflight requires ready Tor pool and Clash with at least one real node")
            self.routing_checks()
            if not self.args.skip_failures:
                self.fault_checks()
            self.audit_checks()
        except (Exception, KeyboardInterrupt) as error:
            self.report["errors"].append(scrub(str(error) or type(error).__name__))
            print("[ERROR] " + scrub(str(error) or type(error).__name__), flush=True)
        finally:
            self.restore()
            self.report["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            self.report["passed"] = (not self.report["errors"] and bool(self.report["checks"])
                                     and all(row["passed"] for row in self.report["checks"]))
            self.args.output.parent.mkdir(parents=True, exist_ok=True)
            self.args.output.write_text(json.dumps(scrub(self.report), ensure_ascii=False, indent=2) + "\n")
            print(f"Report: {self.args.output}", flush=True)
        return 0 if self.report["passed"] else 1


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project-dir", type=Path, default=root)
    parser.add_argument("--jwt-key", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8787")
    parser.add_argument("--task-id", help="Existing idle task used instead of creating a temporary one")
    parser.add_argument("--recording-port", type=int, default=8788)
    parser.add_argument("--ready-timeout", type=int, default=300)
    parser.add_argument("--skip-failures", action="store_true", help="Do not stop services; this scope does not certify fail-closed behavior")
    parser.add_argument("--output", type=Path, default=Path("/tmp/artex-egress-routing-check.json"))
    args = parser.parse_args()
    args.jwt_key = args.jwt_key or args.project_dir / "jwt.key"
    # Convert ordinary SIGTERM into an unwind so finally can restore the stack.
    def terminate(*_):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, terminate)
    return Verification(args).run()


if __name__ == "__main__":
    sys.exit(main())
