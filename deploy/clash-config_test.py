#!/usr/bin/env python3
"""Strict Clash import, persistence and runtime-policy regression checks."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

spec = importlib.util.spec_from_file_location("clash_config", Path(__file__).with_name("clash-config.py"))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def proxy(name="test-node"):
    return {"name": name, "type": "http", "server": "proxy.example", "port": 8888}


class StrictConfigTests(unittest.TestCase):
    def test_discard_subscription_rules_and_groups(self):
        source = {"proxies": [proxy()], "rules": ["MATCH,DIRECT"], "mode": "direct",
                  "proxy-groups": [{"name": "unsafe", "type": "select", "proxies": ["DIRECT"]}],
                  "listeners": [{"type": "http", "listen": "0.0.0.0"}], "script": {"code": "anything"}}
        compiled = config.compile_config(config.load_nodes(yaml.safe_dump(source).encode()), "x" * 64)
        self.assertEqual(compiled["rules"], ["MATCH,CLASH_OUT"])
        self.assertEqual(compiled["mode"], "rule")
        self.assertNotIn("listeners", compiled)
        self.assertNotIn("script", compiled)
        self.assertEqual(compiled["proxy-groups"][0]["proxies"], ["test-node"])
        self.assertEqual(compiled["proxy-groups"][0]["empty-fallback"], "REJECT")
        self.assertFalse(compiled["allow-lan"])
        self.assertEqual(compiled["bind-address"], "127.0.0.1")

    def test_no_nodes_rejects_instead_of_empty_group_direct_default(self):
        compiled = config.compile_config([], "x" * 64)
        self.assertEqual(compiled["rules"], ["MATCH,REJECT"])
        self.assertEqual(compiled["proxy-groups"], [])

    def test_direct_and_pseudo_nodes_rejected(self):
        for kind in ["direct", "compatible", "dns", "reject", "pass", "relay"]:
            with self.subTest(kind=kind), self.assertRaises(config.ConfigError):
                config.load_nodes(yaml.safe_dump({"proxies": [{**proxy(), "type": kind}]}).encode())

    def test_reserved_and_duplicate_names_rejected(self):
        for name in ["DIRECT", "direct", "COMPATIBLE", "CLASH_OUT", "REJECT"]:
            with self.subTest(name=name), self.assertRaises(config.ConfigError):
                config.load_nodes(yaml.safe_dump({"proxies": [proxy(name)]}).encode())
        with self.assertRaises(config.ConfigError):
            config.load_nodes(yaml.safe_dump({"proxies": [proxy(), proxy()]}).encode())

    def test_duplicate_yaml_and_cyclic_alias_rejected(self):
        for text in ["proxies: []\nproxies: []", "proxies: &cycle\n  - *cycle\n"]:
            with self.subTest(text=text), self.assertRaises(config.ConfigError):
                config.load_nodes(text.encode())

    def test_provider_only_does_not_become_direct(self):
        with self.assertRaises(config.ConfigError):
            config.load_nodes(b'proxy-providers: {remote: {type: http, url: "https://example.invalid"}}')

    def test_dialer_references_removed(self):
        node = {**proxy(), "dialer-proxy": "DIRECT", "interface-name": "eth0", "routing-mark": 10}
        parsed = config.load_nodes(yaml.safe_dump({"proxies": [node]}).encode())[0]
        for key in ["dialer-proxy", "interface-name", "routing-mark"]:
            self.assertNotIn(key, parsed)

    def test_invalid_server_and_ports(self):
        cases = [{"port": True}, {"port": 9.2}, {"port": 65536}, {"port": 0},
                 {"server": "user:password@proxy.example"}, {"server": "proxy.example\ninjected"}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(config.ConfigError):
                config.load_nodes(yaml.safe_dump({"proxies": [{**proxy(), **change}]}).encode())

    def test_http_upstream_has_concrete_node(self):
        node = config.upstream_node("http://user:pass%3Aword@host.docker.internal:7897")
        self.assertEqual(node["type"], "http")
        self.assertEqual(node["server"], "host.docker.internal")
        self.assertEqual(node["password"], "pass:word")
        self.assertFalse(node["udp"])


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state"
        self.directory.mkdir(mode=0o700)
        self.legacy = Path(self.temp.name) / "legacy.yaml"
        self.environment = mock.patch.dict(os.environ, {
            "ARTEX_CLASH_LEGACY_CONFIG": str(self.legacy), "ARTEX_CLASH_UPSTREAM": "",
            "ARTEX_MIHOMO_BINARY": str(Path(self.temp.name) / "not-installed"), "ARTEX_CLASH_ENABLED": "1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_saved_subscription_beats_environment_bootstrap(self):
        saved = {"proxies": [proxy("saved-node")]}
        (self.directory / "nodes.yaml").write_text(yaml.safe_dump(saved))
        with mock.patch.dict(os.environ, {"ARTEX_CLASH_UPSTREAM": "http://host.docker.internal:7897"}):
            self.assertEqual(config.source_nodes(self.directory)[0]["name"], "saved-node")

    def test_empty_placeholder_can_bootstrap_real_upstream(self):
        self.legacy.write_text("proxies: []\nrules: [MATCH,DIRECT]\n")
        original = self.legacy.read_bytes()
        with mock.patch.dict(os.environ, {"ARTEX_CLASH_UPSTREAM": "http://host.docker.internal:7897"}):
            nodes = config.source_nodes(self.directory)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(self.legacy.read_bytes(), original)

    def test_secret_is_persistent_and_files_private(self):
        first = config.secret_for(self.directory)
        config.save_compiled(self.directory, [proxy()], persist_nodes=True)
        self.assertEqual(first, config.secret_for(self.directory))
        for name in ["controller.secret", "nodes.yaml", "config.yaml"]:
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)

    def test_invalid_import_leaves_good_files_unchanged_and_redacts_error(self):
        config.save_compiled(self.directory, [proxy()], persist_nodes=True)
        before = {p.name: p.read_bytes() for p in self.directory.iterdir() if p.is_file()}
        source = io.BytesIO(b'proxies: [!!python/object/apply:os.system ["secret-must-not-print"]]')
        output, errors = io.StringIO(), io.StringIO()
        argv = ["clash-config.py", "import", "--directory", str(self.directory)]
        with mock.patch("sys.argv", argv), mock.patch("sys.stdin", type("Input", (), {"buffer": source})()), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = config.main()
        self.assertEqual(code, 2)
        self.assertNotIn("secret-must-not-print", errors.getvalue())
        for name, data in before.items():
            self.assertEqual((self.directory / name).read_bytes(), data)

    def test_invalid_saved_source_prepares_reject_config(self):
        (self.directory / "nodes.yaml").write_text("proxies: [{name: bad, type: direct}]")
        argv = ["clash-config.py", "prepare", "--directory", str(self.directory)]
        with mock.patch("sys.argv", argv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(config.main(), 0)
        self.assertEqual(yaml.safe_load((self.directory / "config.yaml").read_text())["rules"], ["MATCH,REJECT"])
        self.assertFalse(config.status(self.directory)["ready"])

    def controller_status(self, *, mode="rule", selected="test-node", selected_type="Http", rules=None):
        config.save_compiled(self.directory, [proxy()], persist_nodes=True)
        responses = {
            "/proxies": {"proxies": {"CLASH_OUT": {"type": "Selector", "now": selected, "all": ["test-node"]},
                                      "test-node": {"type": selected_type}, "DIRECT": {"type": "Direct"}}},
            "/configs": {"mode": mode},
            "/rules": {"rules": rules if rules is not None else [{"type": "Match", "proxy": "CLASH_OUT"}]},
        }

        def open_request(request, timeout):
            path = request.full_url.removeprefix("http://127.0.0.1:9090")
            return contextlib.closing(io.BytesIO(json.dumps(responses[path]).encode()))

        opener = type("Opener", (), {"open": staticmethod(open_request)})()
        with mock.patch.object(config.urllib.request, "build_opener", return_value=opener), \
                mock.patch.object(config.socket, "create_connection"):
            return config.status(self.directory)

    def test_runtime_status_checks_real_node_and_does_not_emit_secret(self):
        state = self.controller_status()
        self.assertTrue(state["ready"])
        self.assertNotIn(config.secret_for(self.directory), json.dumps(state))

    def test_runtime_direct_selection_or_mode_fails_closed(self):
        self.assertFalse(self.controller_status(selected="DIRECT")["ready"])
        self.assertFalse(self.controller_status(mode="direct")["ready"])

    def test_runtime_rule_mutation_fails_closed(self):
        self.assertFalse(self.controller_status(rules=[{"type": "Match", "proxy": "DIRECT"}])["ready"])

    def test_runtime_pseudo_node_cannot_impersonate_saved_proxy(self):
        for kind in ["Direct", "Compatible", "DNS", "Pass", "Relay"]:
            with self.subTest(kind=kind):
                self.assertFalse(self.controller_status(selected_type=kind)["ready"])


if __name__ == "__main__":
    unittest.main()
