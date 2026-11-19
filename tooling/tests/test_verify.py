"""Unit tests for the shape verifier (src/verify.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import verify
from verify import BUNDLE_FILE, Issue, parse_document, verify_bundle, verify_document

TOOLING = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLING.parent
SMOKE = TOOLING / "tests" / "smoke"
SAMPLE = SMOKE / "pcf-2026-0001"
CONFORMANCE = SMOKE / "conformance"
EXPECTED = json.loads((CONFORMANCE / "expected.json").read_text())


@pytest.fixture
def doc() -> dict:
    """The smoke sample's document: conforms to the spec with no warnings."""
    return json.loads((SAMPLE / BUNDLE_FILE).read_text())


def codes(issues: list[Issue], level: str | None = None) -> list[tuple[str, str]]:
    return sorted((i.code, i.path) for i in issues if level is None or i.level == level)


def write_bundle(root: Path, doc: dict, companions: bool = True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / BUNDLE_FILE).write_text(json.dumps(doc))
    if companions:
        for section, key in verify.COMPANION_FIELDS:
            target = root / doc[section][key]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("")
    return root


# --------------------------------------------------------------------------- #
# Spec mirror and reference documents
# --------------------------------------------------------------------------- #


class TestReferenceDocuments:
    def test_embedded_schema_matches_yaml_spec(self):
        spec = yaml.safe_load((REPO_ROOT / "sharur-bundle-spec.yaml").read_text())
        assert verify.SCHEMA == spec

    def test_smoke_sample_is_clean_even_when_strict(self):
        report = verify_bundle(SAMPLE)
        assert report.issues == []
        assert report.ok(strict=True)

    def test_repo_example_conforms_but_has_placeholders(self):
        report = verify_bundle(REPO_ROOT / "sharur-bundle.json", check_files=False)
        assert report.errors == []
        assert not report.ok(strict=True)
        assert {i.code for i in report.warnings} == {"placeholder", "format"}
        assert ("format", "target.commit") in codes(report.warnings)

    def test_repo_example_has_no_companion_files(self):
        report = verify_bundle(REPO_ROOT / "sharur-bundle.json")
        assert codes(report.errors) == sorted(
            ("file-missing", f"{s}.{k}") for s, k in verify.COMPANION_FIELDS
        )


@pytest.mark.parametrize("case", sorted(EXPECTED), ids=lambda c: c.removesuffix(".json"))
def test_conformance_case(case):
    """Each fixture must produce exactly the listed errors and warnings."""
    report = verify_bundle(CONFORMANCE / case, check_files=False)
    expected = EXPECTED[case]
    assert [list(c) for c in codes(report.errors)] == expected["errors"]
    assert [list(c) for c in codes(report.warnings)] == expected["warnings"]
    if case.startswith("invalid/"):
        assert not report.ok()
    else:
        assert report.ok() and not report.ok(strict=True)


def test_every_conformance_fixture_is_listed():
    on_disk = {p.relative_to(CONFORMANCE).as_posix() for p in CONFORMANCE.glob("*/*.json")}
    assert on_disk == set(EXPECTED)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


class TestParseDocument:
    def test_valid(self):
        doc, issues = parse_document('{"a": 1}')
        assert doc == {"a": 1} and issues == []

    def test_invalid_json(self):
        doc, issues = parse_document("{")
        assert doc is None and codes(issues) == [("json", "")]

    @pytest.mark.parametrize("const", ["NaN", "Infinity", "-Infinity"])
    def test_non_standard_constants_rejected(self, const):
        doc, issues = parse_document(f'{{"seed": {const}}}')
        assert doc is None and codes(issues) == [("json", "")]

    def test_duplicate_keys_reported_at_any_depth(self):
        _, issues = parse_document('{"a": {"b": 1, "b": 2}, "c": 1, "c": 1}')
        assert codes(issues) == [("duplicate-key", "b"), ("duplicate-key", "c")]


# --------------------------------------------------------------------------- #
# Spec errors
# --------------------------------------------------------------------------- #


class TestSpecErrors:
    def test_clean_document(self, doc):
        assert verify_document(doc) == []

    @pytest.mark.parametrize("value", [[], "x", 1, None])
    def test_document_must_be_object(self, value):
        assert codes(verify_document(value)) == [("type", "")]

    def test_every_missing_field_is_reported(self, doc):
        del doc["oracle"]
        del doc["target"]["build"]["recipe"]
        del doc["verdict"]
        assert codes(verify_document(doc)) == [
            ("missing", "oracle"),
            ("missing", "target.build.recipe"),
            ("missing", "verdict"),
        ]

    @pytest.mark.parametrize(
        "path,value,expected",
        [
            ("exploit.steps", 1.0, "expected integer, got number"),
            ("exploit.steps", False, "expected integer, got boolean"),
            ("replay.deterministic", "true", "expected boolean, got string"),
            ("source.tool", None, "expected string, got null"),
            ("exploit.inputs", {}, "expected list, got object"),
            ("environment", [], "expected object, got list"),
        ],
    )
    def test_type_errors(self, doc, path, value, expected):
        section, key = path.split(".") if "." in path else (None, path)
        (doc[section] if section else doc)[key] = value
        issues = verify_document(doc)
        assert [(i.code, i.path, i.message) for i in issues if i.level == "error"] == [("type", path, expected)]

    def test_empty_inputs_list_is_valid(self, doc):
        doc["exploit"]["inputs"] = []
        assert verify_document(doc) == []

    @pytest.mark.parametrize("value", ["High", "critical", "", 3, None, ["high"]])
    def test_severity_enum(self, doc, value):
        doc["reachability"]["severity"] = value
        assert codes(verify_document(doc), "error") == [("enum", "reachability.severity")]

    @pytest.mark.parametrize("value", ["reproduced", "not_reproduced"])
    def test_verdict_enum_accepts_both_values(self, doc, value):
        doc["verdict"] = value
        assert verify_document(doc) == []

    # "a/../poc.py" resolves inside the bundle but is still rejected: a plain
    # "no '..' component" rule is easier for every consumer to apply correctly.
    @pytest.mark.parametrize(
        "value", ["/abs/poc.py", "../poc.py", "a/../../poc.py", "a/../poc.py", "a\\poc.py", "C:poc.py"]
    )
    def test_unsafe_companion_paths(self, doc, value):
        doc["exploit"]["harness"] = value
        assert codes(verify_document(doc), "error") == [("path", "exploit.harness")]

    @pytest.mark.parametrize("value", ["poc.py", "scripts/poc.py", "./poc.py"])
    def test_safe_companion_paths(self, doc, value):
        doc["exploit"]["harness"] = value
        assert verify_document(doc) == []


# --------------------------------------------------------------------------- #
# Recommendation warnings
# --------------------------------------------------------------------------- #


class TestWarnings:
    @pytest.mark.parametrize(
        "commit,ok",
        [("a" * 40, True), ("0" * 64, True), ("a1b2c3", False), ("A" * 40, False), ("g" * 40, False)],
    )
    def test_commit_format(self, doc, commit, ok):
        doc["target"]["commit"] = commit
        assert codes(verify_document(doc)) == ([] if ok else [("format", "target.commit")])

    @pytest.mark.parametrize(
        "digest,ok",
        [
            ("sha256:" + "0" * 64, True),
            ("sha512:" + "a" * 128, True),
            ("sha256:abc", False),
            ("0" * 64, False),
            ("sha256:" + "Z" * 64, False),
        ],
    )
    def test_image_digest_format(self, doc, digest, ok):
        doc["target"]["build"]["image_digest"] = digest
        assert codes(verify_document(doc)) == ([] if ok else [("format", "target.build.image_digest")])

    @pytest.mark.parametrize(
        "ts,ok",
        [
            ("2026-11-19T00:00:00Z", True),
            ("2026-11-19T00:00:00.123456Z", True),
            ("2026-11-19T00:00:00+00:00", True),
            ("2026-11-19T00:00:00", False),
            ("2026-11-19T00:00:00+01:00", False),
            ("2026-11-19", False),
            ("2026-13-01T00:00:00Z", False),
            ("2026-02-29T00:00:00Z", False),
            ("2028-02-29T00:00:00Z", True),
        ],
    )
    def test_started_timestamp(self, doc, ts, ok):
        doc["audit"]["started"] = ts
        assert codes(verify_document(doc)) == ([] if ok else [("format", "audit.started")])

    @pytest.mark.parametrize("steps,ok", [(1, True), (12, True), (0, False), (-3, False)])
    def test_steps_positive(self, doc, steps, ok):
        doc["exploit"]["steps"] = steps
        assert codes(verify_document(doc)) == ([] if ok else [("format", "exploit.steps")])

    def test_egress(self, doc):
        doc["environment"]["egress"] = "enabled"
        assert codes(verify_document(doc)) == [("egress", "environment.egress")]

    @pytest.mark.parametrize("value", ["", "   ", "...", "git@..."])
    def test_placeholders(self, doc, value):
        doc["source"]["tool"] = value
        assert codes(verify_document(doc)) == [("placeholder", "source.tool")]

    def test_placeholder_in_list(self, doc):
        doc["exploit"]["inputs"] = ["ok", "..."]
        assert codes(verify_document(doc)) == [("placeholder", "exploit.inputs[1]")]

    def test_placeholder_does_not_also_raise_format_warning(self, doc):
        doc["target"]["commit"] = "..."
        assert codes(verify_document(doc)) == [("placeholder", "target.commit")]

    def test_unknown_fields(self, doc):
        doc["spec_version"] = "0.1.0"
        doc["target"]["build"]["arch"] = "arm64"
        assert codes(verify_document(doc)) == [
            ("unknown-field", "spec_version"),
            ("unknown-field", "target.build.arch"),
        ]

    def test_warnings_never_make_a_document_invalid(self, doc):
        doc["target"]["commit"] = "abc"
        doc["environment"]["egress"] = "enabled"
        doc["extra"] = True
        report = verify.VerifyReport("x", verify_document(doc))
        assert report.ok() and not report.ok(strict=True)


# --------------------------------------------------------------------------- #
# Bundles on disk
# --------------------------------------------------------------------------- #


class TestVerifyBundle:
    def test_directory_and_file_paths_agree(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc)
        assert verify_bundle(bundle).issues == verify_bundle(bundle / BUNDLE_FILE).issues == []

    def test_any_file_name_is_accepted(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc)
        (bundle / BUNDLE_FILE).rename(bundle / "producer-output.json")
        assert verify_bundle(bundle / "producer-output.json").issues == []

    def test_missing_document_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            verify_bundle(tmp_path)
        with pytest.raises(FileNotFoundError):
            verify_bundle(tmp_path / "nope.json")

    def test_missing_companion_files(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc)
        (bundle / "trace.jsonl").unlink()
        (bundle / "fix.diff").unlink()
        assert codes(verify_bundle(bundle).issues) == [
            ("file-missing", "fix.patch"),
            ("file-missing", "replay.trace"),
        ]

    def test_skip_files(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc, companions=False)
        assert verify_bundle(bundle, check_files=False).issues == []
        assert len(verify_bundle(bundle).errors) == len(verify.COMPANION_FIELDS)

    def test_companion_must_be_a_file(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc)
        (bundle / "actions.log").unlink()
        (bundle / "actions.log").mkdir()
        assert codes(verify_bundle(bundle).issues) == [("file-missing", "audit.actions")]

    def test_unsafe_path_is_not_also_looked_up(self, tmp_path, doc):
        (tmp_path / "outside.py").write_text("")
        doc["exploit"]["harness"] = "../outside.py"
        bundle = write_bundle(tmp_path / "b", {**doc, "exploit": {**doc["exploit"], "harness": "poc.py"}})
        (bundle / BUNDLE_FILE).write_text(json.dumps(doc))
        assert codes(verify_bundle(bundle).issues) == [("path", "exploit.harness")]

    def test_non_utf8_document(self, tmp_path):
        (tmp_path / BUNDLE_FILE).write_bytes(b"\xff\xfe{}")
        assert codes(verify_bundle(tmp_path).issues) == [("json", "")]

    def test_verifier_never_executes_bundle_code(self, tmp_path, doc):
        bundle = write_bundle(tmp_path / "b", doc)
        (bundle / "poc.py").write_text("open('ran', 'w').close()\nraise SystemExit(1)\n")
        verify_bundle(bundle)
        assert not (bundle / "ran").exists() and not Path("ran").exists()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


class TestCLI:
    def test_valid_bundle(self, capsys):
        assert verify.main([str(SAMPLE)]) == 0
        assert capsys.readouterr().out.startswith(f"{SAMPLE}: valid (0 error(s), 0 warning(s))")

    def test_invalid_bundle_lists_issues(self, capsys):
        assert verify.main(["--skip-files", str(CONFORMANCE / "invalid/missing-section.json")]) == 1
        out = capsys.readouterr().out
        assert "INVALID (1 error(s), 0 warning(s))" in out
        assert "error[missing] oracle: required field is missing" in out

    def test_strict_fails_on_warnings(self):
        case = str(CONFORMANCE / "warnings/short-commit.json")
        assert verify.main(["--skip-files", case]) == 0
        assert verify.main(["--skip-files", "--strict", case]) == 1

    def test_json_output(self, capsys):
        case = str(CONFORMANCE / "warnings/egress-enabled.json")
        assert verify.main(["--skip-files", "--format", "json", str(SAMPLE), case]) == 0
        out = json.loads(capsys.readouterr().out)
        assert [r["valid"] for r in out] == [True, True]
        assert out[1]["warnings"] == [
            {
                "level": "warning",
                "code": "egress",
                "path": "environment.egress",
                "message": "egress is 'enabled'; expected 'disabled' or a justification",
            }
        ]

    def test_one_invalid_bundle_fails_the_run(self):
        args = ["--skip-files", str(SAMPLE), str(CONFORMANCE / "invalid/truncated.json")]
        assert verify.main(args) == 1

    def test_unreadable_path_exits_two(self, tmp_path, capsys):
        assert verify.main([str(SAMPLE), str(tmp_path / "missing")]) == 2
        captured = capsys.readouterr()
        assert "no bundle document" in captured.err
        assert f"{SAMPLE}: valid" in captured.out

    def test_no_paths_is_a_usage_error(self):
        with pytest.raises(SystemExit) as exc:
            verify.main([])
        assert exc.value.code == 2

