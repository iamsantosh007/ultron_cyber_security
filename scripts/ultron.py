#!/usr/bin/env python3
"""Ultron's local assessment ledger. Standard library only; never executes a PoC."""

import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import sys
from urllib.parse import quote, unquote, urlsplit

VERSION = "0.2.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = {"candidate", "confirmed", "rejected", "resolved"}
COVERAGE = {"planned", "running", "tested", "inconclusive", "blocked", "skipped", "not-applicable"}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


class Invalid(ValueError):
    """Invalid assessment or unsafe/ambiguous artifact path."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def text_fields(obj, fields, label):
    require(isinstance(obj, dict), f"{label} must be an object")
    for key in fields:
        require(nonempty(obj.get(key)), f"{label}.{key} must be a nonempty string")


def enum(value, options, label):
    require(isinstance(value, str) and value in options, f"Invalid {label}")


def array(value, label):
    require(isinstance(value, list), f"{label} must be an array")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def local_ip(value, allow_private=False):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    # Mapped addresses, link-local, unspecified, multicast, and reserved blocks
    # must not inherit Python's broader is_private classification.
    if getattr(address, "ipv4_mapped", None) is not None:
        return False
    return address.is_loopback or (allow_private and any(
        address.version == network.version and address in network for network in PRIVATE_NETWORKS))


def canonical_url(value):
    require(nonempty(value), "URL must be a nonempty string")
    require(value.isascii() and not re.search(r"[\s\x00-\x1f\x7f\\]", value), "Ambiguous URL characters")
    try:
        parsed = urlsplit(value)
        require(parsed.scheme in {"http", "https"}, "Only HTTP(S) targets are supported")
        require(parsed.hostname and parsed.username is None and parsed.password is None,
                "URL must have a host and no embedded credentials")
        require(not parsed.fragment, "URL fragments are not supported")
        host = parsed.hostname.lower()
        require("%" not in host and not host.endswith("."), "Ambiguous hostname")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        require(parsed.port != 0, "Port zero is not a target")
        try:
            address = ipaddress.ip_address(host)
            host = str(address)
        except ValueError:
            require(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host), "Invalid hostname")
            # Reject alternative numeric IP forms accepted differently by clients.
            require(not re.fullmatch(r"[0-9.]+", host) and not host.startswith("0x"), "Ambiguous numeric host")
        display_host = f"[{host}]" if ":" in host else host
        origin = f"{parsed.scheme}://{display_host}:{port}"
        path = parsed.path or "/"
        require(not re.search(r"%(?![0-9a-fA-F]{2})", path), "Malformed path encoding")
        # Scope checks deliberately refuse traversal/encoded separators. Raw
        # traversal probes need separate manual transport review, never a bypass flag.
        decoded = unquote(path, errors="strict")
        require(not re.search(r"%(?:2e|2f|5c|25)", decoded, re.I), "Nested path encoding")
        require(not re.search(r"%(?:2f|5c)", path, re.I), "Encoded path separator")
        require("\\" not in decoded and not re.search(r"[\x00-\x1f\x7f]", decoded), "Unsafe path")
        require(all(part not in {".", ".."} for part in decoded.split("/")), "Path traversal is outside the scope helper")
        require(not decoded.startswith("//"), "Ambiguous absolute path")
        return origin, decoded, host, port, parsed.query
    except (ValueError, UnicodeError) as exc:
        raise Invalid(str(exc)) from exc


def resolve(host, port):
    return sorted({row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


def make_target(url, allow_private=False, resolver=resolve):
    origin, path, host, port, query = canonical_url(url)
    require(not query, "Scope targets cannot contain a query")
    addresses = resolver(host, port)
    require(addresses and all(local_ip(a, allow_private) for a in addresses),
            "Target must resolve only to loopback or explicitly included private-LAN addresses")
    return {"origin": origin, "base_path": path.rstrip("/") or "/", "addresses": addresses}


def validate_targets(assessment):
    require(type(assessment.get("allow_private")) is bool, "assessment.allow_private must be boolean")
    targets = array(assessment.get("targets"), "assessment.targets")
    require(targets or assessment["mode"] == "code-audit", "Runtime assessments need a target")
    seen = set()
    for target in targets:
        text_fields(target, ("origin", "base_path"), "target")
        origin, path, _, _, query = canonical_url(target["origin"])
        require(path == "/" and not query and origin == target["origin"], "Target origin must be canonical, including port")
        require(target["base_path"].startswith("/") and "?" not in target["base_path"], "Invalid base_path")
        _, base, _, _, _ = canonical_url(origin + target["base_path"])
        require(base == target["base_path"], "base_path must be decoded and canonical")
        addresses = array(target.get("addresses"), "target.addresses")
        require(addresses and all(isinstance(a, str) and local_ip(a, assessment["allow_private"]) for a in addresses),
                "Non-local or invalid pinned address")
        key = (origin, base)
        require(key not in seen, "Duplicate scope target")
        seen.add(key)


def check_scope(assessment, url, resolver=resolve):
    validate_targets(assessment)
    origin, path, host, port, _ = canonical_url(url)
    matches = [target for target in assessment["targets"] if target["origin"] == origin and (
        target["base_path"] == "/" or path == target["base_path"].rstrip("/") or
        path.startswith(target["base_path"].rstrip("/") + "/"))]
    require(matches, "URL is outside recorded origins/base paths")
    addresses = resolver(host, port)
    require(addresses, "Target has no resolved addresses")
    require(any(set(addresses) <= set(target["addresses"]) for target in matches), "DNS resolution differs from recorded addresses")
    return {"origin": origin, "path": path, "addresses": addresses,
            "note": "Preflight only: pin the actual connection and enforce redirects, proxies and subrequests separately."}


def relative_path(value):
    require(nonempty(value) and "\\" not in value and ":" not in value, "Path must be relative POSIX syntax")
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == path.as_posix() and path.parts and
            all(p not in {".", ".."} for p in path.parts), "Path must stay inside its root")
    require(not re.search(r"[\x00-\x1f\x7f]", value), "Invalid path characters")
    return path


def evidence_file(root, value):
    relative = relative_path(value)
    require(relative.parts[0] == "evidence" and len(relative.parts) > 1, "Evidence must be under evidence/")
    root = Path(root).resolve()
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), "Evidence symlinks are not allowed")
    require(current.resolve().is_relative_to(root), "Evidence escapes run directory")
    require(current.is_file(), "Evidence file does not exist")
    return current


def evidence_refs(refs, root, label, required=False):
    array(refs, label)
    require(not required or refs, f"{label} needs evidence")
    for ref in refs:
        text_fields(ref, ("path", "sha256"), label)
        require(re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]), f"{label} has an invalid SHA-256")
        require(digest(evidence_file(root, ref["path"])) == ref["sha256"], f"{label}: evidence checksum mismatch")


def fingerprint(finding):
    # Stable across line, title, severity, and local finding-ID changes. Surface
    # uses a route template/symbol, never a disposable object ID.
    identity = [finding[key].strip() for key in ("rule_id", "surface", "boundary")]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()


def validate(data, root):
    require(isinstance(data, dict) and type(data.get("schema_version")) is int and data["schema_version"] == 1,
            "Unsupported or missing schema_version")
    assessment = data.get("assessment")
    text_fields(assessment, ("id", "project", "mode", "created_at", "revision"), "assessment")
    enum(assessment["mode"], {"pentest", "code-audit", "retest"}, "assessment.mode")
    require(type(assessment.get("complete")) is bool, "assessment.complete must be boolean")
    try:
        require(dt.datetime.fromisoformat(assessment["created_at"]).tzinfo is not None, "created_at requires a timezone")
    except ValueError as exc:
        raise Invalid("created_at must be an ISO 8601 timestamp with timezone") from exc
    validate_targets(assessment)
    coverage_ids = set()
    for row in array(data.get("coverage"), "coverage"):
        text_fields(row, ("id", "surface", "check", "status", "notes"), "coverage")
        require(row["id"] not in coverage_ids, "Duplicate coverage ID")
        coverage_ids.add(row["id"])
        enum(row["status"], COVERAGE, "coverage.status")
        evidence_refs(row.get("evidence", []), root, "coverage.evidence", row["status"] == "tested")
    for item in array(data.get("cleanup", []), "cleanup"):
        text_fields(item, ("resource", "status", "notes"), "cleanup")
        enum(item["status"], {"removed", "retained", "pending"}, "cleanup.status")
    ids, identities = set(), set()
    for finding in array(data.get("findings"), "findings"):
        text_fields(finding, ("id", "rule_id", "surface", "boundary", "title", "severity", "status", "validation",
                              "description", "impact", "remediation", "regression_test"), "finding")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", finding["rule_id"]), "Invalid rule_id")
        enum(finding["status"], STATUSES, "finding.status")
        enum(finding["severity"], SEVERITIES, "finding.severity")
        enum(finding["validation"], {"static", "runtime"}, "finding.validation")
        for field in ("proof", "verification"):
            if field in finding:
                require(isinstance(finding[field], dict), f"{field} must be an object")
        if "proof" in finding:
            text_fields(finding["proof"], ("expected", "observed", "control"), "proof")
            steps = array(finding["proof"].get("steps"), "proof.steps")
            require(steps and all(nonempty(s) for s in steps), "proof.steps needs reproduction steps")
        if "verification" in finding:
            text_fields(finding["verification"], ("result", "reproducer", "control"), "verification")
            enum(finding["verification"]["result"], {"reproduced", "not-reproduced", "blocked", "not-run"}, "verification.result")
            evidence_refs(finding["verification"].get("evidence", []), root, "verification.evidence")
        require(finding["id"] not in ids, "Duplicate finding ID")
        ids.add(finding["id"])
        identity = fingerprint(finding)
        require(identity not in identities, "Duplicate finding identity; consolidate the root cause")
        identities.add(identity)
        if "location" in finding:
            location = finding["location"]
            text_fields(location, ("path",), "location")
            relative_path(location["path"])
            require(type(location.get("line")) is int and location["line"] > 0, "location.line must be a positive integer")
        conclusive = finding["status"] in {"confirmed", "resolved"}
        evidence_refs(finding.get("evidence", []), root, "finding.evidence", conclusive)
        if conclusive:
            require(finding["validation"] == "runtime", "Static evidence cannot confirm an exploit or a runtime fix")
            proof = finding.get("proof")
            text_fields(proof, ("expected", "observed", "control"), "proof")
            steps = array(proof.get("steps"), "proof.steps")
            require(steps and all(nonempty(s) for s in steps), "proof.steps needs reproduction steps")
            verification = finding.get("verification")
            text_fields(verification, ("result", "reproducer", "control"), "verification")
            expected = "reproduced" if finding["status"] == "confirmed" else "not-reproduced"
            require(verification["result"] == expected, f"{finding['status']} requires {expected} verification")
            evidence_refs(verification.get("evidence"), root, "verification.evidence", True)
            require({e["path"] for e in finding["evidence"]}.isdisjoint(
                {e["path"] for e in verification["evidence"]}), "Verification needs a separate replay artifact")
    return data


def load_run(path):
    path = Path(path)
    file = path / "assessment.json" if path.is_dir() else path
    return validate(read_json(file), file.parent), file.parent


def write_new(path, content):
    """Do not overwrite reports, follow leaf symlinks, or create public evidence."""
    fd = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def init_run(path, project, targets, mode="pentest", allow_private=False, resolver=resolve):
    target_records = [make_target(url, allow_private, resolver) for url in targets]
    data = {"schema_version": 1, "assessment": {
        "id": "ULTRON-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(3).hex(),
        "project": project, "mode": mode, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "revision": "unknown", "complete": False, "allow_private": allow_private, "targets": target_records},
        "coverage": [], "findings": [], "cleanup": []}
    validate(data, path)
    root = Path(path)
    root.mkdir(mode=0o700)  # Refuse an existing run; never clobber a prior assessment.
    (root / "evidence").mkdir(mode=0o700)
    write_new(root / "assessment.json", json.dumps(data, indent=2) + "\n")
    return data


def md(value):
    # Escape active HTML, links/images, tables and formatting from app-controlled data.
    value = html.escape(str(value), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", value).replace("\r", "").replace("\n", "<br>")


def markdown(data):
    assessment = data["assessment"]
    lines = [f"# Ultron assessment — {md(assessment['project'])}", "",
             f"Run: {md(assessment['id'])} · Revision: {md(assessment['revision'])}", "",
             f"Mode: {md(assessment['mode'])} · Complete: {assessment['complete']}", "",
             "Validated records and checksums support review; they do not independently attest that a claim is true.", "",
             "## Scope", ""]
    lines.extend(f"- {md(t['origin'])}{md(t['base_path'])}" for t in assessment["targets"])
    if not assessment["targets"]:
        lines.append("Source review only; no runtime target.")
    for status in ("confirmed", "candidate", "resolved", "rejected"):
        findings = sorted((f for f in data["findings"] if f["status"] == status),
                          key=lambda f: (-SEVERITIES.index(f["severity"]), f["id"]))
        lines.extend(["", f"## {status.capitalize()} ({len(findings)})", ""])
        for finding in findings:
            lines.extend([f"### {md(finding['id'])} — [{finding['severity'].upper()}] {md(finding['title'])}", ""])
            for label, key in (("Rule", "rule_id"), ("Surface", "surface"), ("Boundary", "boundary"),
                               ("Validation", "validation"), ("Description", "description"), ("Impact", "impact"),
                               ("Remediation", "remediation"), ("Regression check", "regression_test")):
                lines.append(f"- **{label}:** {md(finding[key])}")
            if "location" in finding:
                lines.append(f"- **Source:** {md(finding['location']['path'])}:{finding['location']['line']}")
            if isinstance(finding.get("proof"), dict):
                proof = finding["proof"]
                for key in ("expected", "observed", "control"):
                    lines.append(f"- **{key.capitalize()}:** {md(proof.get(key, 'not recorded'))}")
                lines.extend(["", "Reproduction:", ""])
                lines.extend(f"{i}. {md(step)}" for i, step in enumerate(proof.get("steps", []), 1))
            refs = list(finding.get("evidence", []))
            if isinstance(finding.get("verification"), dict):
                verify = finding["verification"]
                lines.extend(["", f"Verification: {md(verify.get('result', 'not-run'))}; "
                              f"{md(verify.get('reproducer', 'unknown'))}; control: {md(verify.get('control', 'unknown'))}"])
                refs.extend(verify.get("evidence", []))
            lines.extend(["", "Evidence (relative to the run directory):", ""])
            lines.extend(f"- {md(ref['path'])} — SHA-256 `{ref['sha256']}`" for ref in refs)
            lines.append("")
    lines.extend(["", "## Coverage", "", "| Surface | Check | Status | Notes |", "|---|---|---|---|"])
    for row in data["coverage"]:
        lines.append("| " + " | ".join(md(row[k]) for k in ("surface", "check", "status", "notes")) + " |")
    lines.extend(["", "## Cleanup", ""])
    for item in data.get("cleanup", []):
        lines.append(f"- {md(item['resource'])}: {md(item['status'])} — {md(item['notes'])}")
    if not data.get("cleanup"):
        lines.append("No cleanup actions recorded; verify whether the engagement created fixtures.")
    lines.extend(["", "No confirmed vulnerabilities means none were confirmed in the recorded checks; it is not a security certification.", ""])
    return "\n".join(lines)


def sarif(data, include_candidates=False):
    selected = [f for f in data["findings"] if f["status"] == "confirmed" or
                (include_candidates and f["status"] == "candidate")]
    eligible = [f for f in selected if "location" in f]
    rule_ids = sorted({f["rule_id"] for f in eligible})
    results = []
    for finding in eligible:
        location = finding["location"]
        results.append({"ruleId": finding["rule_id"], "ruleIndex": rule_ids.index(finding["rule_id"]),
            "level": "note" if finding["status"] == "candidate" else
                     ("error" if finding["severity"] in {"high", "critical"} else "warning" if finding["severity"] == "medium" else "note"),
            "message": {"text": f"[{finding['status']}; {finding['validation']}] {finding['title']}. "
                        f"{finding['description']} Remediation: {finding['remediation']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(location["path"], safe="/")},
                                                 "region": {"startLine": location["line"]}}}],
            "partialFingerprints": {"ultronIdentity/v1": fingerprint(finding)},
            "properties": {"ultronId": finding["id"], "status": finding["status"],
                           "validation": finding["validation"], "severity": finding["severity"]}})
    # GitHub consumes primaryLocationLineHash, not arbitrary custom fingerprints.
    # Its upload-sarif action can add that source-based hash; do not fabricate it.
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Ultron", "version": VERSION, "informationUri": "https://github.com/iamsantosh007/ultron_cyber_security",
                            "rules": [{"id": rule, "shortDescription": {"text": rule}} for rule in rule_ids]}},
        "results": results, "properties": {"assessmentId": data["assessment"]["id"],
                                           "omittedWithoutSourceLocation": len(selected) - len(eligible)}}]}


def compare(before, after):
    require(before["assessment"]["project"] == after["assessment"]["project"], "Cannot compare different project identities")
    old = {fingerprint(f): f for f in before["findings"]}
    new = {fingerprint(f): f for f in after["findings"]}
    output = {key: [] for key in ("new", "persistent", "resolved", "regressed", "unverified", "untested")}
    for identity, finding in new.items():
        previous = old.get(identity)
        if previous is None:
            state = "new"
        elif finding["status"] == "resolved":
            state = "resolved"
        elif finding["status"] == "confirmed":
            state = "regressed" if previous["status"] == "resolved" else "persistent"
        else:
            state = "unverified"
        output[state].append({"id": finding["id"], "previous_id": previous["id"] if previous else None,
                              "status": finding["status"], "fingerprint": identity, "title": finding["title"]})
    for identity, finding in old.items():
        if identity not in new:
            output["untested"].append({"id": finding["id"], "fingerprint": identity, "title": finding["title"]})
    return output


def gate(data, threshold):
    if any(f["status"] == "confirmed" and SEVERITIES.index(f["severity"]) >= SEVERITIES.index(threshold)
           for f in data["findings"]):
        return 1, "Confirmed findings meet the failure threshold"
    if (not data["assessment"]["complete"] or not any(row["status"] == "tested" for row in data["coverage"]) or
        any(row["status"] not in {"tested", "not-applicable"} for row in data["coverage"]) or
        any(f["status"] == "candidate" for f in data["findings"])):
        return 3, "Assessment is incomplete or has unresolved candidates"
    return 0, "No confirmed findings at the threshold in the completed recorded scope"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a private assessment directory; no requests are sent")
    init.add_argument("run")
    init.add_argument("--project", required=True, help="Stable project identity, reused across retests")
    init.add_argument("--mode", choices=["pentest", "code-audit", "retest"], default="pentest")
    init.add_argument("--target", action="append", default=[])
    init.add_argument("--allow-private", action="store_true", help="Include explicitly authorized private-LAN targets")
    for name, help_text in (("validate", "Validate records and evidence checksums"),
                            ("scope", "Check a URL against recorded scope; not a transport firewall"),
                            ("evidence", "Hash one sanitized evidence file already in the run directory"),
                            ("report", "Render Markdown or SARIF without executing reproduction steps"),
                            ("gate", "Check confirmed severity and assessment completeness")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("run")
        if name == "scope":
            command.add_argument("url")
        if name == "evidence":
            command.add_argument("path", help="Relative evidence/ path")
        if name == "report":
            command.add_argument("--format", choices=["markdown", "sarif"], default="markdown")
            command.add_argument("--include-candidates", action="store_true", help="Include labeled candidates in SARIF")
            command.add_argument("--output", required=True, help="New output file; never overwrites")
        if name == "gate":
            command.add_argument("--fail-on", choices=SEVERITIES, default="high")
    baseline = commands.add_parser("compare", help="Compare finding identities; absence never means fixed")
    baseline.add_argument("before")
    baseline.add_argument("after")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result = init_run(args.run, args.project, args.target, args.mode, args.allow_private)
            print(json.dumps({"run": str(Path(args.run).resolve()), "id": result["assessment"]["id"]}))
            return 0
        if args.command == "evidence":
            root = Path(args.run)
            print(json.dumps({"path": args.path, "sha256": digest(evidence_file(root, args.path))}))
            return 0
        if args.command == "compare":
            before, _ = load_run(args.before)
            after, _ = load_run(args.after)
            print(json.dumps(compare(before, after), indent=2))
            return 0
        data, _ = load_run(args.run)
        if args.command == "validate":
            print(f"Valid assessment: {len(data['findings'])} findings, {len(data['coverage'])} coverage records; evidence checksums match")
        elif args.command == "scope":
            print(json.dumps(check_scope(data["assessment"], args.url), indent=2))
        elif args.command == "report":
            output = markdown(data) if args.format == "markdown" else json.dumps(sarif(data, args.include_candidates), indent=2) + "\n"
            write_new(args.output, output)
            print(f"Wrote {args.output}")
        elif args.command == "gate":
            code, message = gate(data, args.fail_on)
            print(message)
            return code
        return 0
    except (Invalid, OSError, ValueError) as exc:
        # No document contents or credentials in error output.
        print(f"Ultron: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
