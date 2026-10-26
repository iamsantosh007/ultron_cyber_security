import importlib.util
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validate_plugin", ROOT / "scripts/validate_plugin.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def test_real_package_references_and_metadata(self):
        self.assertEqual(package.validate(ROOT), [])

    def test_validator_detects_broken_link_after_code_fence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / ".claude-plugin", root / ".claude-plugin")
            (root / "skills/example").mkdir(parents=True)
            (root / "skills/example/SKILL.md").write_text(
                '---\nname: example\ndescription: Example workflow.\n---\n'
                '# Example\n```text\n[not a real link](placeholder.md)\n```\n'
                '[real reference](missing.md)\n')
            errors = package.validate(root)
            self.assertEqual(len(errors), 1, errors)
            self.assertIn("missing.md", errors[0])

    def test_bundled_shell_examples_parse_without_execution(self):
        if not shutil.which("bash"):
            self.skipTest("bash not available")
        for path in (ROOT / "skills").rglob("*.md"):
            for snippet in re.findall(r"```sh\n(.*?)\n```", path.read_text(), re.S):
                result = subprocess.run(["bash", "-n"], input=snippet, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")

    def test_sink_searches_are_literal_and_valid(self):
        if not shutil.which("rg"):
            self.skipTest("ripgrep not available")
        text = (ROOT / "skills/code-audit/references/sink-catalog.md").read_text()
        for command in re.findall(r"\*\*Search:\*\* `([^`]+)`", text):
            argv = shlex.split(command)
            self.assertEqual(argv[0], "rg")
            self.assertIn(argv[1], ("-n", "-l"))
            # Run a regex on inert stdin, never a shell or a source repository.
            result = subprocess.run(["rg", "-n", argv[2]], input="harmless text", text=True, capture_output=True)
            self.assertIn(result.returncode, (0, 1), result.stderr)


if __name__ == "__main__":
    unittest.main()
