"""Shape verifier for Sharur bundles.

Checks that a bundle conforms to the open spec (``sharur-bundle-spec.yaml``)
without running anything in it. It is safe to point at untrusted bundles, and it
uses only the Python standard library.

Every problem is reported as an :class:`Issue` with a level, a stable code, and
the dotted path of the offending field.

**Errors** are violations of the spec. The bundle does not conform:

    json            not valid JSON, or uses NaN/Infinity
    duplicate-key   an object repeats a key, so readers may disagree on its value
    missing         a field the spec defines is absent
    type            a field has the wrong type
    enum            a value is not one of the allowed values
    path            a companion path is absolute or escapes the bundle directory
    file-missing    a referenced companion file does not exist

**Warnings** are conventions that DOCS.md recommends but the spec does not yet
require. ``--strict`` treats them as errors:

    unknown-field   a field the spec does not define
    format          commit, image digest, timestamp or step count not in the
                    recommended form
    placeholder     a value is empty or still the ``...`` placeholder
    egress          the exploit was recorded with network egress not disabled

Exit codes for the CLI:
    0  every bundle conforms
    1  at least one bundle does not conform
    2  a path could not be read
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

__all__ = [
    "BUNDLE_FILE",
    "COMPANION_FIELDS",
    "SCHEMA",
    "Issue",
    "VerifyReport",
    "main",
    "parse_document",
    "verify_bundle",
    "verify_document",
]

BUNDLE_FILE = "sharur-bundle.json"

# Mirror of sharur-bundle-spec.yaml. tests/test_verify.py asserts the two are
# identical, so edit the YAML first and then update this to match.
SCHEMA: dict[str, Any] = {
    "finding_id": "string",
    "source": {"tool": "string", "original_id": "string", "class": "string"},
    "target": {
        "repo": "string",
        "commit": "string",
        "build": {"recipe": "string", "image_digest": "string"},
    },
    "environment": {"microvm": "string", "kernel": "string", "egress": "string"},
    "exploit": {"harness": "string", "inputs": ["string"], "steps": "integer"},
    "oracle": {
        "kind": "string",
        "signal": "string",
        "minimal_effect": "boolean",
        "observed": "string",
    },
    "replay": {"seed": "integer", "deterministic": "boolean", "trace": "string"},
    "reachability": {
        "exposed": "boolean",
        "entrypoint": "string",
        "severity": {"enum": ["informational", "low", "medium", "high"]},
    },
    "dedup": {"root_cause_hash": "string", "cluster": "string"},
    "fix": {"patch": "string", "poc_now_fails": "boolean", "tests_pass": "boolean"},
    "audit": {"scope_signed_by": "string", "started": "string", "actions": "string"},
    "verdict": {"enum": ["not_reproduced", "reproduced"]},
}

# Fields whose value is a path to a companion file inside the bundle directory.
COMPANION_FIELDS = (
    ("exploit", "harness"),
    ("replay", "trace"),
    ("fix", "patch"),
    ("audit", "actions"),
)

_TYPES = {"string": str, "integer": int, "boolean": bool}
_JSON_TYPE_NAMES = {
    dict: "object", list: "list", str: "string", int: "integer",
    float: "number", bool: "boolean", type(None): "null",
}

_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-f]{32,}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$")


@dataclass(frozen=True)
class Issue:
    level: str  # "error" | "warning"
    code: str
    path: str  # dotted field path; "" for the document as a whole
    message: str

    def __str__(self) -> str:
        return f"{self.path or '(document)'}: {self.message}"


@dataclass
class VerifyReport:
    source: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    def ok(self, strict: bool = False) -> bool:
        return not (self.issues if strict else self.errors)

    def to_dict(self, strict: bool = False) -> dict[str, Any]:
        return {
            "source": self.source,
            "valid": self.ok(strict),
            "strict": strict,
            "errors": [asdict(i) for i in self.errors],
            "warnings": [asdict(i) for i in self.warnings],
        }


def _type_name(value: Any) -> str:
    return _JSON_TYPE_NAMES.get(type(value), type(value).__name__)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse_document(text: str) -> tuple[Any, list[Issue]]:
    """Parse bundle JSON strictly.

    Returns ``(doc, issues)``. ``doc`` is None if the text is not valid JSON.
    Duplicate keys and the non-standard constants NaN/Infinity, which Python's
    ``json`` module accepts by default, are reported as errors.
    """
    issues: list[Issue] = []

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                issues.append(Issue("error", "duplicate-key", key, f"key {key!r} appears more than once"))
            seen[key] = value
        return seen

    def reject_constant(name: str) -> Any:
        raise ValueError(f"{name} is not valid JSON")

    try:
        doc = json.loads(text, object_pairs_hook=pairs_hook, parse_constant=reject_constant)
    except ValueError as exc:  # JSONDecodeError is a ValueError subclass
        return None, [Issue("error", "json", "", f"not valid JSON: {exc}")]
    return doc, issues


# --------------------------------------------------------------------------- #
# Spec conformance (errors)
# --------------------------------------------------------------------------- #


def _check(value: Any, spec: Any, path: str, issues: list[Issue]) -> None:
    if isinstance(spec, dict) and set(spec) == {"enum"}:
        if not isinstance(value, str) or value not in spec["enum"]:
            allowed = ", ".join(spec["enum"])
            issues.append(Issue("error", "enum", path, f"{value!r} is not one of: {allowed}"))
        return
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            issues.append(Issue("error", "type", path, f"expected object, got {_type_name(value)}"))
            return
        for key, sub in spec.items():
            if key not in value:
                issues.append(Issue("error", "missing", _join(path, key), "required field is missing"))
            else:
                _check(value[key], sub, _join(path, key), issues)
        for key in sorted(value.keys() - spec.keys()):
            issues.append(Issue("warning", "unknown-field", _join(path, key), "field is not defined by the spec"))
        return
    if isinstance(spec, list):
        if not isinstance(value, list):
            issues.append(Issue("error", "type", path, f"expected list, got {_type_name(value)}"))
            return
        for i, item in enumerate(value):
            _check(item, spec[0], f"{path}[{i}]", issues)
        return
    # bool is a subclass of int in Python; an integer field must not accept it.
    if not isinstance(value, _TYPES[spec]) or (spec == "integer" and isinstance(value, bool)):
        issues.append(Issue("error", "type", path, f"expected {spec}, got {_type_name(value)}"))


def _get(doc: dict[str, Any], dotted: str) -> Any:
    """Return the value at ``dotted`` if every step exists, else None."""
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _check_companion_paths(doc: dict[str, Any], issues: list[Issue]) -> None:
    for section, key in COMPANION_FIELDS:
        value = _get(doc, f"{section}.{key}")
        if not isinstance(value, str) or not value:
            continue
        p = PurePosixPath(value)
        if p.is_absolute() or "\\" in value or ".." in p.parts or re.match(r"^[A-Za-z]:", value):
            issues.append(
                Issue("error", "path", f"{section}.{key}", f"{value!r} must be a relative path inside the bundle")
            )


# --------------------------------------------------------------------------- #
# Recommended conventions (warnings)
# --------------------------------------------------------------------------- #


def _warn(issues: list[Issue], code: str, path: str, message: str) -> None:
    issues.append(Issue("warning", code, path, message))


def _check_recommendations(doc: dict[str, Any], issues: list[Issue]) -> None:
    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, _join(path, k))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{path}[{i}]")
        elif isinstance(value, str) and (value.strip() == "" or "..." in value):
            _warn(issues, "placeholder", path, f"{value!r} looks empty or like a placeholder")

    walk(doc, "")

    commit = _get(doc, "target.commit")
    if isinstance(commit, str) and "..." not in commit and not _COMMIT_RE.match(commit):
        _warn(issues, "format", "target.commit", f"{commit!r} is not a full lowercase commit hash (40 or 64 hex)")

    digest = _get(doc, "target.build.image_digest")
    if isinstance(digest, str) and "..." not in digest and not _DIGEST_RE.match(digest):
        _warn(issues, "format", "target.build.image_digest", f"{digest!r} is not of the form <algorithm>:<hex>")

    started = _get(doc, "audit.started")
    if isinstance(started, str) and "..." not in started and not _is_utc_timestamp(started):
        _warn(issues, "format", "audit.started", f"{started!r} is not an ISO 8601 UTC timestamp")

    steps = _get(doc, "exploit.steps")
    if isinstance(steps, int) and not isinstance(steps, bool) and steps < 1:
        _warn(issues, "format", "exploit.steps", f"{steps} should be at least 1")

    egress = _get(doc, "environment.egress")
    if isinstance(egress, str) and egress != "disabled":
        _warn(issues, "egress", "environment.egress", f"egress is {egress!r}; expected 'disabled' or a justification")


def _is_utc_timestamp(value: str) -> bool:
    if not _UTC_RE.match(value):
        return False
    # The regex checks the shape; strptime rejects impossible dates (2026-02-30).
    try:
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def verify_document(doc: Any) -> list[Issue]:
    """Check an already-parsed bundle document. Does not touch the filesystem."""
    if not isinstance(doc, dict):
        return [Issue("error", "type", "", f"expected object, got {_type_name(doc)}")]
    issues: list[Issue] = []
    _check(doc, SCHEMA, "", issues)
    _check_companion_paths(doc, issues)
    _check_recommendations(doc, issues)
    return issues


def verify_bundle(path: Path | str, *, check_files: bool = True) -> VerifyReport:
    """Verify a bundle given as a directory or as the path to its JSON file.

    Companion files are resolved relative to the directory holding the JSON. Set
    ``check_files=False`` to check the document's shape alone.

    Raises ``FileNotFoundError`` if there is no bundle document at ``path``.
    """
    path = Path(path)
    doc_path = path / BUNDLE_FILE if path.is_dir() else path
    if not doc_path.is_file():
        raise FileNotFoundError(f"no bundle document at {doc_path}")
    report = VerifyReport(source=str(path))
    try:
        text = doc_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        report.issues.append(Issue("error", "json", "", f"not UTF-8: {exc}"))
        return report

    doc, issues = parse_document(text)
    report.issues.extend(issues)
    if doc is None:
        return report
    report.issues.extend(verify_document(doc))

    if check_files and isinstance(doc, dict):
        bad_paths = {i.path for i in report.issues if i.code == "path"}
        for section, key in COMPANION_FIELDS:
            value = _get(doc, f"{section}.{key}")
            dotted = f"{section}.{key}"
            if isinstance(value, str) and value and dotted not in bad_paths:
                if not (doc_path.parent / value).is_file():
                    report.issues.append(
                        Issue("error", "file-missing", dotted, f"companion file {value!r} not found")
                    )
    return report


def _format_text(report: VerifyReport, strict: bool) -> str:
    status = "valid" if report.ok(strict) else "INVALID"
    counts = f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)"
    lines = [f"{report.source}: {status} ({counts})"]
    for issue in report.errors + report.warnings:
        lines.append(f"  {issue.level}[{issue.code}] {issue}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sharur-verify",
        description="Check that Sharur bundles conform to the spec. Runs nothing in the bundle.",
    )
    parser.add_argument("paths", nargs="+", help="bundle directories or sharur-bundle.json files")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--skip-files", action="store_true", help="do not check that companion files exist")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = []
    unreadable = False
    for p in args.paths:
        try:
            reports.append(verify_bundle(p, check_files=not args.skip_files))
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            unreadable = True

    if args.format == "json":
        print(json.dumps([r.to_dict(args.strict) for r in reports], indent=2))
    else:
        for r in reports:
            print(_format_text(r, args.strict))

    if unreadable:
        return 2
    return 0 if all(r.ok(args.strict) for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
