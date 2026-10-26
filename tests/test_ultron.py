"""Behavioral tests for scope, proof records, exports, and retest semantics."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ultron.py"
spec = importlib.util.spec_from_file_location("ultron", SCRIPT)
ultron = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ultron)


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "run"
        self.data = ultron.init_run(self.root, "test-app", ["http://localhost:3000/api"],
                                   resolver=lambda *_: ["127.0.0.1"])
        self.refs = []
        for name, text in (("probe.txt", "A retrieved B's marked fixture; own-object control passed"),
                           ("replay.txt", "Fresh independent replay: second marked fixture retrieved")):
            path = self.root / "evidence" / name
            path.write_text(text)
            self.refs.append({"path": f"evidence/{name}", "sha256": ultron.digest(path)})
        self.finding = {
            "id": "ULTRON-001", "rule_id": "CWE-639", "surface": "GET /api/orders/{id}",
            "boundary": "cross-tenant order read", "title": "Cross-tenant order disclosure",
            "severity": "high", "status": "confirmed", "validation": "runtime",
            "description": "Account A can retrieve a disposable order owned by B.",
            "impact": "Private order fields cross a tenant boundary.",
            "remediation": "Filter order lookups by the authenticated tenant.",
            "regression_test": "A is denied B's order while both owners can read their own.",
            "location": {"path": "src/orders.py", "line": 12}, "evidence": [self.refs[0]],
            "proof": {"expected": "Deny access", "observed": "B's marked data returned", "control": "Owner reads passed",
                      "steps": ["Create disposable orders for A and B", "Read B's order using A's test credentials"]},
            "verification": {"result": "reproduced", "reproducer": "Separate verifier replay with fresh fixture",
                             "control": "Owner control passed on the fresh fixture", "evidence": [self.refs[1]]}}
        self.data["findings"] = [self.finding]
        self.data["assessment"]["complete"] = True
        self.data["coverage"] = [{"id": "S1", "surface": "GET /api/orders/{id}", "check": "tenant isolation",
                                 "status": "tested", "notes": "Two disposable identities", "evidence": [self.refs[0]]}]

    def save(self):
        (self.root / "assessment.json").write_text(json.dumps(self.data))

    def test_complete_evidence_record_validates(self):
        self.assertIs(ultron.validate(self.data, self.root), self.data)

    def test_incomplete_proofs_cannot_be_confirmed(self):
        for field in ("proof", "verification", "evidence"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                del data["findings"][0][field]
                with self.assertRaises(ultron.Invalid):
                    ultron.validate(data, self.root)

    def test_static_review_cannot_claim_exploit_or_fix(self):
        for status in ("confirmed", "resolved"):
            with self.subTest(status=status):
                self.finding.update(status=status, validation="static")
                with self.assertRaisesRegex(ultron.Invalid, "Static"):
                    ultron.validate(self.data, self.root)

    def test_candidate_does_not_require_fabricated_runtime_proof(self):
        self.finding.update(status="candidate", validation="static")
        del self.finding["proof"], self.finding["verification"]
        self.finding["evidence"] = []
        ultron.validate(self.data, self.root)

    def test_verification_cannot_reuse_original_artifact(self):
        self.finding["verification"]["evidence"] = self.finding["evidence"]
        with self.assertRaisesRegex(ultron.Invalid, "separate replay"):
            ultron.validate(self.data, self.root)

    def test_tampered_evidence_is_detected(self):
        (self.root / "evidence" / "replay.txt").write_text("changed")
        with self.assertRaisesRegex(ultron.Invalid, "checksum"):
            ultron.validate(self.data, self.root)

    def test_escaping_evidence_paths_and_symlinks_are_rejected(self):
        external = Path(self.temp.name) / "private.txt"
        external.write_text("not evidence")
        (self.root / "evidence" / "link.txt").symlink_to(external)
        for path in ("../private.txt", "/tmp/private.txt", "evidence/../../private.txt", "evidence/link.txt",
                     "evidence/./probe.txt", "evidence//probe.txt", "evidence\\probe.txt"):
            with self.subTest(path=path), self.assertRaises(ultron.Invalid):
                ultron.evidence_file(self.root, path)

    def test_duplicate_identities_are_rejected(self):
        second = copy.deepcopy(self.finding)
        second["id"] = "ULTRON-002"
        self.data["findings"].append(second)
        with self.assertRaisesRegex(ultron.Invalid, "identity"):
            ultron.validate(self.data, self.root)

    def test_malformed_input_returns_validation_errors(self):
        mutations = [lambda d: d.update(schema_version=True), lambda d: d.update(findings={}),
                     lambda d: d.update(assessment=None), lambda d: d["assessment"].update(complete="yes"),
                     lambda d: d["findings"][0].update(status=[]),
                     lambda d: d["findings"][0]["location"].update(line=True),
                     lambda d: d["findings"][0]["location"].update(path="https://target/path"),
                     lambda d: d["coverage"][0].update(evidence=[])]
        for mutation in mutations:
            data = copy.deepcopy(self.data)
            mutation(data)
            with self.subTest(data=data), self.assertRaises(ultron.Invalid):
                ultron.validate(data, self.root)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ultron.Invalid, "Duplicate JSON"):
            json.loads('{"status":"candidate","status":"confirmed"}', object_pairs_hook=ultron.unique_object)

    def test_stable_identity_ignores_line_title_and_severity(self):
        new = copy.deepcopy(self.finding)
        new.update(id="ULTRON-999", title="Improved title", severity="critical")
        new["location"]["line"] = 100
        self.assertEqual(ultron.fingerprint(new), ultron.fingerprint(self.finding))
        new["boundary"] = "administrator role change"
        self.assertNotEqual(ultron.fingerprint(new), ultron.fingerprint(self.finding))

    def test_missing_finding_is_untested_not_resolved(self):
        after = copy.deepcopy(self.data)
        after["findings"] = []
        result = ultron.compare(self.data, after)
        self.assertEqual(len(result["untested"]), 1)
        self.assertEqual(result["resolved"], [])

    def test_downgrade_to_candidate_is_unverified(self):
        after = copy.deepcopy(self.data)
        after["findings"][0]["status"] = "candidate"
        self.assertEqual(len(ultron.compare(self.data, after)["unverified"]), 1)

    def test_resolved_requires_successful_control_and_replay_evidence(self):
        after = copy.deepcopy(self.data)
        finding = after["findings"][0]
        finding["status"] = "resolved"
        with self.assertRaisesRegex(ultron.Invalid, "not-reproduced"):
            ultron.validate(after, self.root)
        finding["verification"]["result"] = "not-reproduced"
        ultron.validate(after, self.root)
        self.assertEqual(len(ultron.compare(self.data, after)["resolved"]), 1)
        self.assertEqual(len(ultron.compare(after, self.data)["regressed"]), 1)

    def test_different_projects_cannot_be_compared(self):
        after = copy.deepcopy(self.data)
        after["assessment"]["project"] = "unrelated"
        with self.assertRaises(ultron.Invalid):
            ultron.compare(self.data, after)

    def test_sarif_exports_only_confirmed_source_locations_by_default(self):
        result = ultron.sarif(self.data)
        self.assertEqual(result["version"], "2.1.0")
        self.assertEqual(len(result["runs"][0]["results"]), 1)
        self.finding["status"] = "candidate"
        self.assertEqual(ultron.sarif(self.data)["runs"][0]["results"], [])
        candidate = ultron.sarif(self.data, True)["runs"][0]["results"][0]
        self.assertEqual(candidate["level"], "note")
        self.assertIn("candidate", candidate["message"]["text"])
        del self.finding["location"]
        run = ultron.sarif(self.data, True)["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["properties"]["omittedWithoutSourceLocation"], 1)

    def test_sarif_uri_encodes_special_characters(self):
        self.finding["location"]["path"] = "src/order #1.py"
        result = ultron.sarif(self.data)["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/order%20%231.py")

    def test_markdown_escapes_untrusted_html_and_links(self):
        self.finding["title"] = '<img src="https://untrusted.invalid/x"> ![leak](https://untrusted.invalid)'
        report = ultron.markdown(self.data)
        self.assertNotIn('<img', report)
        self.assertNotIn('![leak](', report)
        self.assertIn("&lt;img", report)

    def test_gate_does_not_clear_missing_or_incomplete_assessments(self):
        self.assertEqual(ultron.gate(self.data, "high")[0], 1)
        self.data["findings"] = []
        self.assertEqual(ultron.gate(self.data, "high")[0], 0)
        self.data["assessment"]["complete"] = False
        self.assertEqual(ultron.gate(self.data, "high")[0], 3)
        self.data["assessment"]["complete"] = True
        for state in ("skipped", "inconclusive", "blocked", "planned", "running"):
            self.data["coverage"][0]["status"] = state
            self.assertEqual(ultron.gate(self.data, "high")[0], 3)
        self.data["coverage"] = []
        self.assertEqual(ultron.gate(self.data, "high")[0], 3)

    def test_gate_cannot_pass_with_only_not_applicable_checks(self):
        self.data["findings"] = []
        self.data["coverage"][0]["status"] = "not-applicable"
        self.assertEqual(ultron.gate(self.data, "high")[0], 3)

    def test_malformed_optional_candidate_proof_is_rejected(self):
        self.finding["status"] = "candidate"
        self.finding["proof"] = {"steps": "not a list"}
        with self.assertRaises(ultron.Invalid):
            ultron.validate(self.data, self.root)

    def test_run_and_reports_are_private_and_not_overwritten(self):
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        path = self.root / "report.md"
        ultron.write_new(path, "original")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            ultron.write_new(path, "replacement")
        self.assertEqual(path.read_text(), "original")
        with self.assertRaises(FileExistsError):
            ultron.init_run(self.root, "same", [], mode="code-audit")

    def test_cli_validate_render_compare_and_gate(self):
        self.save()
        def run(*args):
            return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)
        self.assertEqual(run("validate", self.root).returncode, 0)
        report = self.root / "report.sarif"
        self.assertEqual(run("report", self.root, "--format", "sarif", "--output", report).returncode, 0)
        self.assertEqual(json.loads(report.read_text())["runs"][0]["results"][0]["ruleId"], "CWE-639")
        self.assertEqual(run("report", self.root, "--output", report).returncode, 2)
        self.assertEqual(run("gate", self.root).returncode, 1)
        compared = run("compare", self.root, self.root)
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertEqual(len(json.loads(compared.stdout)["persistent"]), 1)
        (self.root / "evidence" / "probe.txt").write_text("tampered")
        self.assertEqual(run("validate", self.root).returncode, 2)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.assessment = {"mode": "pentest", "allow_private": False, "targets": [
            ultron.make_target("http://localhost:3000/api", resolver=lambda *_: ["127.0.0.1", "::1"])]}

    def test_in_scope_query_and_path(self):
        result = ultron.check_scope(self.assessment, "http://LOCALHOST:3000/api/orders?next=https://ultron.invalid",
                                    resolver=lambda *_: ["127.0.0.1"])
        self.assertEqual(result["origin"], "http://localhost:3000")

    def test_scope_boundaries_are_checked_before_dns(self):
        def unexpected(*_):
            self.fail("Out-of-scope hostname must not be resolved")
        for url in ("http://localhost:3001/api", "https://localhost:3000/api", "http://localhost:3000/apiculture",
                    "http://localhost.evil.invalid:3000/api", "http://user:password@localhost:3000/api"):
            with self.subTest(url=url), self.assertRaises(ultron.Invalid):
                ultron.check_scope(self.assessment, url, resolver=unexpected)

    def test_dns_changes_and_mixed_public_answers_are_rejected(self):
        for addresses in (["8.8.8.8"], ["127.0.0.1", "8.8.8.8"], ["127.0.0.2"]):
            with self.subTest(addresses=addresses), self.assertRaises(ultron.Invalid):
                ultron.check_scope(self.assessment, "http://localhost:3000/api", resolver=lambda *_: addresses)

    def test_numeric_forms_traversal_and_ambiguous_urls_are_rejected(self):
        for url in ("http://2130706433/", "http://127.1/", "http://0x7f000001/", "file:///etc/passwd",
                    "http://localhost:0/", "http://localhost./", "http://localhost/a/../b",
                    "http://localhost/%2e%2e/b", "http://localhost/a%2fb", "http://localhost/%252e%252e/b",
                    "http://localhost/a\\b", "http://localhost/a\nb", "http://localhost/%zz", "http://localhost/#frag"):
            with self.subTest(url=url), self.assertRaises(ultron.Invalid):
                ultron.canonical_url(url)

    def test_only_loopback_and_opted_in_rfc1918_or_ula(self):
        for address in ("127.0.0.1", "::1"):
            self.assertTrue(ultron.local_ip(address))
        for address in ("10.1.2.3", "172.16.1.2", "192.168.1.5", "fd00::1"):
            self.assertFalse(ultron.local_ip(address))
            self.assertTrue(ultron.local_ip(address, True))
        for address in ("0.0.0.0", "::", "169.254.169.254", "fe80::1", "192.0.2.1", "100.64.0.1",
                        "224.0.0.1", "8.8.8.8", "::ffff:127.0.0.1", "::ffff:8.8.8.8"):
            self.assertFalse(ultron.local_ip(address, True), address)

    def test_ipv6_and_default_ports(self):
        origin, _, _, port, _ = ultron.canonical_url("http://[::1]/")
        self.assertEqual((origin, port), ("http://[::1]:80", 80))
        self.assertEqual(ultron.canonical_url("https://localhost/")[0], "https://localhost:443")


if __name__ == "__main__":
    unittest.main()
