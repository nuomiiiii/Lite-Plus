#!/usr/bin/env python3
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import plus_follow


class PlusFollowTests(unittest.TestCase):
    def test_patch_and_minor_bumps(self) -> None:
        self.assertEqual(plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.11"), "0.0.2")
        self.assertEqual(plus_follow.bump_plus("0.0.2", "2.3.11", "2.4.0"), "0.1.0")
        self.assertEqual(plus_follow.bump_plus("0.1.3", "2.4.0", "3.0.0"), "0.2.0")

    def test_refuses_older_or_equal_lite(self) -> None:
        with self.assertRaises(SystemExit):
            plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.10")
        with self.assertRaises(SystemExit):
            plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.9")

    def test_ours_keeps_plus_agent_install_urls(self) -> None:
        ours = (pathlib.Path(__file__).resolve().parent / "follow-ours-web.txt").read_text(encoding="utf-8")
        self.assertIn("src/utils/agentInstall.ts", ours)
        self.assertIn("tests/agentInstall.test.ts", ours)

    def test_ours_keeps_plus_bgp_table(self) -> None:
        server = (pathlib.Path(__file__).resolve().parent / "follow-ours-server.txt").read_text(encoding="utf-8")
        self.assertIn("database/tasks/return_route_bgp_prefixes.json", server)

    def test_c_class_covers_i18n_and_mcp(self) -> None:
        web = (pathlib.Path(__file__).resolve().parent / "follow-c-web.txt").read_text(encoding="utf-8")
        server = (pathlib.Path(__file__).resolve().parent / "follow-c-server.txt").read_text(encoding="utf-8")
        self.assertIn("src/i18n/locales/zh_CN.json", web)
        self.assertIn("web/mcp/oauth.go", server)

    def test_theme_git_ref(self) -> None:
        self.assertEqual(plus_follow.theme_git_ref(""), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("1.2.9"), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("v1.2.9"), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("main"), "main")

    def test_validate_and_rewrite_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "utils").mkdir()
            (root / "utils" / "version.go").write_text('CurrentVersion = "0.0.1"\n', encoding="utf-8")
            plus_follow.write_baseline(
                root / "plus-baseline.json",
                {
                    "plus": "0.0.1",
                    "lite": "2.3.10",
                    "lite_hash": "k8w2n5h",
                    "lite_web": "2.3.10",
                    "lite_web_hash": "",
                    "lite_agent": "2.3.10.0",
                    "lite_theme": "1.2.9",
                },
            )
            plus_follow.validate_baseline(root / "plus-baseline.json")
            plus_follow.rewrite_server(root, "0.0.2", "2.3.11", "2.3.11", "2.3.10.0", "1.2.9", "n8k2m5y", "n8k2m5y")
            self.assertIn('CurrentVersion = "0.0.2"', (root / "utils" / "version.go").read_text(encoding="utf-8"))
            data = plus_follow.validate_baseline(root / "plus-baseline.json")
            self.assertEqual(data["plus"], "0.0.2")
            self.assertEqual(data["lite"], "2.3.11")
            self.assertEqual(data["lite_hash"], "n8k2m5y")
            self.assertEqual(data["lite_web_hash"], "n8k2m5y")

    def test_rewrite_web_keeps_plus_offline_picker_selection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            picker = root / "src" / "components" / "remote"
            tests = root / "tests"
            picker.mkdir(parents=True)
            tests.mkdir()
            (root / "package.json").write_text('{"name": "lite-web", "version": "2.3.10"}\n', encoding="utf-8")
            (picker / "RemoteNodePicker.tsx").write_text(
                "allowOffline?: boolean;\n"
                "const selectable = allowOffline || knownOnline;\n"
                'onClick={() => { if (knownOnline) onSelect(node); }}\n'
                'onKeyDown={(event) => { if (!knownOnline || (event.key !== "Enter" && event.key !== " ")) return; }}\n',
                encoding="utf-8",
            )
            (tests / "remoteNodePicker.test.ts").write_text(
                'assert.equal(pickerSource.includes("if (knownOnline) onSelect(node)"), true);\n'
                'assert.equal(pickerSource.includes(\'event.key !== "Enter" && event.key !== " "\'), true);\n',
                encoding="utf-8",
            )
            plus_follow.rewrite_web(root, "0.1.3", "2.3.10", "2.3.10", "2.3.10.0", "1.2.9", "h7n2w5k", "")
            picker_text = (picker / "RemoteNodePicker.tsx").read_text(encoding="utf-8")
            test_text = (tests / "remoteNodePicker.test.ts").read_text(encoding="utf-8")
            self.assertIn("if (selectable) onSelect(node)", picker_text)
            self.assertNotIn("if (knownOnline) onSelect(node)", picker_text)
            self.assertIn('if (!selectable || (event.key !== "Enter" && event.key !== " "))', picker_text)
            self.assertIn('includes("if (selectable) onSelect(node)"), true', test_text)
            self.assertNotIn('includes("if (knownOnline) onSelect(node)"), true', test_text)

    def test_rewrite_web_keeps_plus_negative_known_online_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            picker = root / "src" / "components" / "remote"
            tests = root / "tests"
            picker.mkdir(parents=True)
            tests.mkdir()
            (root / "package.json").write_text('{"name": "lite-plus-web", "version": "0.1.3"}\n', encoding="utf-8")
            (picker / "RemoteNodePicker.tsx").write_text(
                "allowOffline?: boolean;\n"
                "const selectable = allowOffline || knownOnline;\n"
                "onClick={() => { if (selectable) onSelect(node); }}\n",
                encoding="utf-8",
            )
            (tests / "remoteNodePicker.test.ts").write_text(
                'assert.equal(pickerSource.includes("if (selectable) onSelect(node)"), true);\n'
                'assert.equal(pickerSource.includes("if (knownOnline) onSelect(node)"), false);\n',
                encoding="utf-8",
            )
            plus_follow.preserve_plus_remote_picker(root)
            picker_text = (picker / "RemoteNodePicker.tsx").read_text(encoding="utf-8")
            test_text = (tests / "remoteNodePicker.test.ts").read_text(encoding="utf-8")
            self.assertIn("if (selectable) onSelect(node)", picker_text)
            self.assertNotIn("if (knownOnline) onSelect(node)", picker_text)
            self.assertIn('includes("if (selectable) onSelect(node)"), true', test_text)
            self.assertIn('includes("if (knownOnline) onSelect(node)"), false', test_text)
            self.assertNotIn('includes("if (selectable) onSelect(node)"), false', test_text)

    def test_rewrite_web_leaves_lite_online_only_picker(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            picker = root / "src" / "components" / "remote"
            tests = root / "tests"
            picker.mkdir(parents=True)
            tests.mkdir()
            (root / "package.json").write_text('{"name": "lite-web", "version": "2.3.10"}\n', encoding="utf-8")
            (picker / "RemoteNodePicker.tsx").write_text(
                'onClick={() => { if (knownOnline) onSelect(node); }}\n',
                encoding="utf-8",
            )
            (tests / "remoteNodePicker.test.ts").write_text(
                'assert.equal(pickerSource.includes("if (knownOnline) onSelect(node)"), true);\n',
                encoding="utf-8",
            )
            plus_follow.preserve_plus_remote_picker(root)
            self.assertIn("if (knownOnline) onSelect(node)", (picker / "RemoteNodePicker.tsx").read_text(encoding="utf-8"))
            self.assertIn("if (knownOnline) onSelect(node)", (tests / "remoteNodePicker.test.ts").read_text(encoding="utf-8"))

    def test_rewrite_web_keeps_plus_package_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "package.json").write_text(
                '{"name": "lite-web", "version": "2.3.11"}\n',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"name": "lite-web", "version": "2.3.11", "packages": {"": {"name": "lite-web", "version": "2.3.11"}}}\n',
                encoding="utf-8",
            )
            plus_follow.rewrite_web(root, "0.0.2", "2.3.11", "2.3.11", "2.3.10.0", "1.2.9", "n8k2m5y", "")
            pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg["name"], "lite-plus-web")
            self.assertEqual(pkg["version"], "0.0.2")
            lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
            self.assertEqual(lock["name"], "lite-plus-web")
            self.assertEqual(lock["packages"][""]["version"], "0.0.2")
            data = plus_follow.validate_baseline(root / "plus-baseline.json")
            self.assertEqual(data["lite_hash"], "n8k2m5y")
            self.assertEqual(data["lite_web_hash"], "")

    def test_release_hash_and_same_version_decision(self) -> None:
        self.assertEqual(plus_follow.release_hash("<!-- lite-version-hash: k8w2n5h -->\n"), "k8w2n5h")
        self.assertEqual(plus_follow.release_hash("no marker"), "")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "k8w2n5h", ""), "skip")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "abc1234", ""), "rebuild")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "aaaaaa1", "k8w2n5h", "bbbbbb2"), "wait")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "aaaaaa1", "abc1234", "aaaaaa1"), "wait")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "aaaaaa1", "abc1234", "bbbbbb2"), "rebuild")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "", ""), "skip")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "k8w2n5h", "", "1", "1"), "rebuild")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "k8w2n5h", "", "0", "1"), "wait")
        self.assertEqual(plus_follow.decide_same_version("k8w2n5h", "", "k8w2n5h", "", "1", "0"), "rebuild")
        patched = plus_follow.patch_release_body("<!-- lite-version-hash: k3n8w2h -->\n\nhello\n", "a1b2c3d")
        self.assertTrue(patched.startswith("<!-- lite-version-hash: a1b2c3d -->"))
        value = plus_follow.new_plus_hash()
        self.assertEqual(len(value), 7)
        self.assertNotIn("q", value)
        self.assertRegex(value, r"[a-z]")
        self.assertRegex(value, r"[0-9]")

    def test_merge_json_keeps_plus_and_takes_lite_additions(self) -> None:
        base = {"a": "1", "b": "2", "nested": {"x": "old"}}
        ours = {"a": "plus", "b": "2", "c": "plus-only", "nested": {"x": "old"}}
        theirs = {"a": "1", "b": "lite", "d": "lite-only", "nested": {"x": "old", "y": "new"}}
        merged = plus_follow.merge_json_value(base, ours, theirs)
        self.assertEqual(merged["a"], "plus")
        self.assertEqual(merged["b"], "2")
        self.assertEqual(merged["c"], "plus-only")
        self.assertEqual(merged["d"], "lite-only")
        self.assertEqual(merged["nested"]["y"], "new")
        both = plus_follow.merge_json_value({"k": "old"}, {"k": "plus"}, {"k": "lite"})
        self.assertEqual(both["k"], "plus")


if __name__ == "__main__":
    unittest.main()
