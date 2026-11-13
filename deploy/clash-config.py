#!/usr/bin/python3
"""Compile a node-only Mihomo configuration and inspect it without credentials.

Only concrete proxy nodes are imported. Subscription rules, groups, providers,
listeners and scripts never become part of the executable configuration.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import yaml


MAX_CONFIG_BYTES = 8 * 1024 * 1024
MAX_NODES = 512
GROUP = "CLASH_OUT"
CONCRETE_TYPES = {
    "http", "socks5", "ss", "ssr", "vmess", "vless", "trojan", "snell",
    "hysteria", "hysteria2", "tuic", "wireguard", "ssh", "anytls", "mieru",
}
CONCRETE_API_TYPES = {
    "http", "socks5", "shadowsocks", "shadowsocksr", "vmess", "vless", "trojan",
    "snell", "hysteria", "hysteria2", "tuic", "wireguard", "ssh", "anytls", "mieru",
}
RESERVED_NAMES = {"DIRECT", "COMPATIBLE", "GLOBAL", "REJECT", "REJECT-DROP", "PASS", GROUP}


class ConfigError(ValueError):
    pass


class UniqueLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    pass


def unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise ConfigError("配置键必须为标量") from error
        if duplicate:
            raise ConfigError("配置含重复键")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def checked_tree(value, stack=None, depth=0, budget=None):
    stack = set() if stack is None else stack
    budget = [100000] if budget is None else budget
    budget[0] -= 1
    if depth > 24 or budget[0] < 0:
        raise ConfigError("配置嵌套或条目过多")
    if isinstance(value, (dict, list)):
        if id(value) in stack:
            raise ConfigError("配置不能包含循环别名")
        stack.add(id(value))
        for child in value.values() if isinstance(value, dict) else value:
            checked_tree(child, stack, depth + 1, budget)
        stack.remove(id(value))


def load_nodes(data: bytes) -> list[dict]:
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError("配置超过大小限制")
    try:
        document = yaml.load(data, Loader=UniqueLoader)
    except ConfigError:
        raise
    except (yaml.YAMLError, UnicodeError, RecursionError) as error:
        # YAML diagnostics can contain the offending line, including passwords.
        raise ConfigError("无效的 YAML 配置") from error
    checked_tree(document)
    if not isinstance(document, dict):
        raise ConfigError("需要含 proxies 的 Clash YAML")
    nodes = document.get("proxies", [])
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise ConfigError("proxies 必须为不超过 512 项的列表")
    if not nodes and document.get("proxy-providers"):
        raise ConfigError("请导入已展开真实节点的订阅，不支持仅含 provider 的配置")
    result = []
    names = set()
    for index, value in enumerate(nodes, 1):
        if not isinstance(value, dict):
            raise ConfigError(f"第 {index} 个节点格式无效")
        kind = str(value.get("type", "")).lower()
        if kind not in CONCRETE_TYPES:
            raise ConfigError(f"第 {index} 个节点不是支持的真实代理节点")
        name = value.get("name")
        if (not isinstance(name, str) or not name.strip() or len(name) > 160
                or any(ord(c) < 32 for c in name) or name.upper() in RESERVED_NAMES
                or name in names):
            raise ConfigError(f"第 {index} 个节点名称无效、重复或保留")
        server = value.get("server")
        if (not isinstance(server, str) or not server.strip() or len(server) > 253
                or any(c.isspace() or ord(c) < 32 for c in server)
                or any(c in server for c in "/@")):
            raise ConfigError(f"第 {index} 个节点缺少有效的代理服务器")
        port = value.get("port")
        if isinstance(port, bool) or not isinstance(port, (str, int)):
            raise ConfigError(f"第 {index} 个节点端口无效")
        try:
            port = int(port)
        except (TypeError, ValueError) as error:
            raise ConfigError(f"第 {index} 个节点端口无效") from error
        if not 1 <= port <= 65535:
            raise ConfigError(f"第 {index} 个节点端口无效")
        node = copy.deepcopy(value)
        node.update(type=kind, server=server.strip(), port=port)
        # No references to DIRECT, subscription groups or alternate dialers.
        for key in ["dialer-proxy", "interface-name", "routing-mark"]:
            node.pop(key, None)
        names.add(name)
        result.append(node)
    return result


def upstream_node(raw: str) -> dict:
    try:
        parsed = urllib.parse.urlsplit(raw)
        host, port = parsed.hostname, parsed.port
    except ValueError as error:
        raise ConfigError("Clash 上游地址无效") from error
    if (parsed.scheme not in {"http", "https", "socks5", "socks5h"}
            or not host or not port or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment or any(c.isspace() for c in raw)):
        raise ConfigError("Clash 上游需为带端口的 HTTP 或 SOCKS 代理地址")
    node = {"name": "configured-upstream", "type": "socks5" if parsed.scheme.startswith("socks5") else "http",
            "server": host, "port": port, "udp": False}
    if parsed.scheme == "https":
        node["tls"] = True
    if parsed.username is not None:
        node["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password is not None:
        node["password"] = urllib.parse.unquote(parsed.password)
    return node


def compile_config(nodes: list[dict], secret: str) -> dict:
    config = {
        "mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
        "external-controller": "127.0.0.1:9090", "secret": secret,
        "mode": "rule", "log-level": "warning", "ipv6": False,
        "profile": {"store-selected": True},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False,
                "respect-rules": True, "prefer-h3": False,
                "default-nameserver": ["https://1.1.1.1/dns-query"],
                # Only proxy-node bootstrap bypasses the selected proxy. Target
                # nameserver connections follow MATCH,CLASH_OUT (or REJECT).
                "proxy-server-nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
                "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
        "proxies": copy.deepcopy(nodes), "proxy-groups": [], "rules": ["MATCH,REJECT"],
    }
    if nodes:
        config["proxy-groups"] = [{"name": GROUP, "type": "select",
                                   "proxies": [node["name"] for node in nodes],
                                   "empty-fallback": "REJECT", "disable-udp": True}]
        config["rules"] = ["MATCH," + GROUP]
    return config


def atomic_write(path: Path, value: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=".clash-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def secret_for(directory: Path) -> str:
    path = directory / "controller.secret"
    if path.exists():
        value = path.read_text().strip()
        if len(value) >= 32 and not any(c.isspace() for c in value):
            return value
    value = secrets.token_hex(32)
    atomic_write(path, value.encode() + b"\n")
    return value


def source_nodes(directory: Path) -> list[dict]:
    path = directory / "nodes.yaml"
    upstream = os.environ.get("ARTEX_CLASH_UPSTREAM", "").strip()
    if path.exists():
        nodes = load_nodes(path.read_bytes())
        if nodes or not upstream:
            return nodes
        nodes = [upstream_node(upstream)]
        atomic_write(path, yaml.safe_dump({"proxies": nodes}, allow_unicode=True, sort_keys=False).encode())
        return nodes
    legacy = Path(os.environ.get("ARTEX_CLASH_LEGACY_CONFIG", "/app/data/clash/config.yaml"))
    if legacy.is_file():
        nodes = load_nodes(legacy.read_bytes())
    else:
        nodes = []
    if not nodes and upstream:
        nodes = [upstream_node(upstream)]
    atomic_write(path, yaml.safe_dump({"proxies": nodes}, allow_unicode=True, sort_keys=False).encode())
    return nodes


def save_compiled(directory: Path, nodes: list[dict], persist_nodes=False):
    config = compile_config(nodes, secret_for(directory))
    encoded = yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode()
    binary = os.environ.get("ARTEX_MIHOMO_BINARY", "/usr/local/bin/mihomo")
    if Path(binary).is_file():
        fd, candidate = tempfile.mkstemp(prefix=".validate-", suffix=".yaml", dir=directory)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
            try:
                result = subprocess.run([binary, "-t", "-d", str(directory), "-f", candidate],
                                        capture_output=True, timeout=20, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ConfigError("Mihomo 配置校验未完成，原配置保持不变") from error
            if result.returncode:
                raise ConfigError("Mihomo 配置校验失败，原配置保持不变")
        finally:
            os.unlink(candidate)
    if persist_nodes:
        atomic_write(directory / "nodes.yaml", yaml.safe_dump({"proxies": nodes}, allow_unicode=True, sort_keys=False).encode())
    atomic_write(directory / "config.yaml", encoded)
    return config


def status(directory: Path) -> dict:
    enabled = os.environ.get("ARTEX_CLASH_ENABLED", "0") == "1"
    out = {"enabled": enabled, "ready": False, "node_count": 0, "selected": "", "error": ""}
    if not enabled:
        out["error"] = "Clash 未启用"
        return out
    try:
        nodes = load_nodes((directory / "nodes.yaml").read_bytes())
        out["node_count"] = len(nodes)
        if not nodes:
            raise ConfigError("Clash 无真实代理节点，当前仅拒绝连接")
        secret = (directory / "controller.secret").read_text().strip()
        saved = yaml.load((directory / "config.yaml").read_bytes(), Loader=UniqueLoader)
        if saved != compile_config(nodes, secret):
            raise ConfigError("Clash 运行配置不符合严格代理策略")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def get(path):
            request = urllib.request.Request("http://127.0.0.1:9090" + path,
                                             headers={"Authorization": "Bearer " + secret})
            with opener.open(request, timeout=0.6) as response:
                return json.load(response)

        proxies = get("/proxies").get("proxies", {})
        group = proxies.get(GROUP, {})
        selected = group.get("now", "")
        expected = {node["name"] for node in nodes}
        if group.get("type") != "Selector" or set(group.get("all", [])) != expected or selected not in expected:
            raise ConfigError("Clash 策略组不完整或未选择真实节点")
        actual = proxies.get(selected, {})
        if str(actual.get("type", "")).lower() not in CONCRETE_API_TYPES:
            raise ConfigError("Clash 当前出口不是实际代理节点")
        if get("/configs").get("mode") != "rule":
            raise ConfigError("Clash 未处于受控规则模式")
        rules = get("/rules").get("rules", [])
        if len(rules) != 1 or rules[0].get("type") != "Match" or rules[0].get("proxy") != GROUP:
            raise ConfigError("Clash 规则不符合严格代理策略")
        with socket.create_connection(("127.0.0.1", 7890), timeout=0.3):
            pass
        out.update(ready=True, selected=selected)
    except ConfigError as error:
        out["error"] = str(error)
    except Exception:
        out["error"] = "Clash 未就绪或控制接口不可用"
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "import", "status", "health"])
    parser.add_argument("--directory", type=Path,
                        default=Path(os.environ.get("ARTEX_CLASH_DIR", "/var/lib/artex-clash")))
    parser.add_argument("--input", default="-")
    args = parser.parse_args()
    try:
        if args.action in {"status", "health"}:
            result = status(args.directory)
            print(json.dumps(result, ensure_ascii=False))
            return 1 if args.action == "health" and result["enabled"] and not result["ready"] else 0
        args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(args.directory, 0o700)
        if args.action == "import":
            data = sys.stdin.buffer.read(MAX_CONFIG_BYTES + 1) if args.input == "-" else Path(args.input).read_bytes()
            nodes = load_nodes(data)
            if not nodes:
                raise ConfigError("订阅无真实节点，原配置保持不变")
        else:
            try:
                nodes = source_nodes(args.directory)
            except ConfigError:
                # An invalid saved subscription must not prevent Tor startup or
                # leave an old DIRECT-capable configuration running.
                save_compiled(args.directory, [])
                print('{"ok":true,"node_count":0,"reject_only":true,"error":"Clash 节点配置无效，已使用拒绝策略"}')
                return 0
        save_compiled(args.directory, nodes, persist_nodes=args.action == "import")
        print(json.dumps({"ok": True, "node_count": len(nodes), "reject_only": not nodes}, ensure_ascii=False))
        return 0
    except ConfigError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    except Exception:
        print('{"ok":false,"error":"Clash 配置处理失败，未输出配置内容"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
