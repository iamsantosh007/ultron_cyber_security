#!/usr/bin/env python3
"""Offline checks for Ultron's package, skill entrypoints, and reference graph."""

import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


def validate(root):
    root = Path(root).resolve()
    errors = []
    try:
        manifest = json.loads((root / ".claude-plugin/plugin.json").read_text())
        marketplace = json.loads((root / ".claude-plugin/marketplace.json").read_text())
        if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", "")):
            errors.append("plugin.json: version must be a three-part release version")
        if not manifest.get("description"):
            errors.append("plugin.json: missing description")
        if not marketplace.get("metadata", {}).get("description"):
            errors.append("marketplace.json: missing metadata.description")
        if not any(p.get("name") == manifest.get("name") and p.get("source") == "./" for p in marketplace.get("plugins", [])):
            errors.append("marketplace.json: missing matching root plugin entry")
    except (OSError, ValueError, TypeError) as exc:
        return [f"Manifest error: {exc}"]
    skills = sorted((root / "skills").glob("*/SKILL.md"))
    if not skills:
        errors.append("No skill entrypoints found")
    for skill in skills:
        text = skill.read_text()
        front = re.match(r"\A---\n(.*?)\n---\n", text, re.S)
        if not front:
            errors.append(f"{skill.relative_to(root)}: missing frontmatter")
            continue
        # This repository deliberately uses simple inline name/description fields.
        fields = dict(re.findall(r"^([a-z-]+): (.+)$", front[1], re.M))
        if fields.get("name") != skill.parent.name:
            errors.append(f"{skill.relative_to(root)}: name must match directory")
        if not 1 <= len(fields.get("description", "")) <= 1024:
            errors.append(f"{skill.relative_to(root)}: missing/oversized description")
    documents = list(root.glob("*.md"))
    for folder in ("skills", "references", "docs"):
        documents.extend((root / folder).rglob("*.md"))
    for doc in sorted(documents):
        text = re.sub(r"^```[^\n]*\n.*?^```\s*$", "", doc.read_text(), flags=re.M | re.S)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            parsed = urlsplit(target)
            if parsed.scheme or not parsed.path:
                continue
            path = (doc.parent / unquote(parsed.path)).resolve()
            if not path.is_relative_to(root) or not path.exists():
                errors.append(f"{doc.relative_to(root)}: broken/outside reference {target}")
    # Keep the CLI and distributable version aligned without executing plugin code.
    helper = root / "scripts/ultron.py"
    if helper.exists():
        version = re.search(r'^VERSION = "([^"]+)"', helper.read_text(), re.M)
        if not version or version[1] != manifest["version"]:
            errors.append("CLI version differs from plugin.json")
    return errors


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    errors = validate(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)
    print("Plugin manifests, skill entrypoints, versions, and local Markdown references are valid.")
