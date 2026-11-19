"""Unit tests for the reference replayer (src/replay.py)."""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import replay
from replay import (
    BUNDLE_FILE,
    SIGNATURE_FILE,
    BundleError,
    LocalBackend,
    compute_digest,
    evaluate_oracle,
    load_bundle,
    sign_digest,
    verify_signature,
)

TOOLING = Path(__file__).resolve().parents[1]
REPO_ROOT = TOOLING.parent
SMOKE_BUNDLE = TOOLING / "tests" / "smoke" / "pcf-2026-0001"
SMOKE_PUBKEY = TOOLING / "tests" / "smoke" / "keys" / "sample-signer.pub.pem"

ASAN_REPORT = (
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050\n"
    "WRITE of size 8 at 0x602000000050 thread T0\n"
)

# A harness that prints an ASan report when its input says "boom", reads the
# seed from the environment, and can be told to hang.
HARNESS = textwrap.dedent(
    """
    import os, sys
    mode = open(sys.argv[1]).read().strip()
    if mode == "seed":
        mode = "boom" if os.environ.get("SHARUR_REPLAY_SEED") == "42" else "ok"
    if mode == "boom":
        sys.stderr.write("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\\n")
        sys.exit(1)
    if mode == "sleep":
        import time; time.sleep(30)
    print("ok")
    """
)


def _base_doc() -> dict:
    return json.loads((REPO_ROOT / "sharur-bundle.json").read_text())


def make_bundle(root: Path, *, mode: str = "boom", verdict: str = "reproduced", **overrides) -> Path:
    """Write a minimal valid bundle directory under ``root`` and return it."""
    bundle = root / "bundle"
    bundle.mkdir(parents=True)
    doc = _base_doc()
    doc["exploit"] = {"harness": "poc.py", "inputs": ["input.txt"], "steps": 1}
    doc["verdict"] = verdict
    for dotted, value in overrides.items():
        section, key = dotted.split("__")
        doc[section][key] = value
    (bundle / BUNDLE_FILE).write_text(json.dumps(doc, indent=2))
    (bundle / "poc.py").write_text(HARNESS)
    (bundle / "input.txt").write_text(mode)
    for name in ("trace.jsonl", "fix.diff", "actions.log"):
        (bundle / name).write_text("")
    return bundle


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def sign(bundle: Path, private_pem: bytes) -> None:
    (bundle / SIGNATURE_FILE).write_text(sign_digest(compute_digest(bundle), private_pem))


# --------------------------------------------------------------------------- #
# Loading (shape checks themselves are tested in test_verify.py)
# --------------------------------------------------------------------------- #


class TestLoadBundle:
    def test_smoke_bundle_loads_without_warnings(self):
        doc, warnings = load_bundle(SMOKE_BUNDLE)
        assert doc["verdict"] == "reproduced"
        assert warnings == []

    def test_spec_warnings_are_returned_not_raised(self, tmp_path):
        bundle = make_bundle(tmp_path, environment__egress="enabled")
        _, warnings = load_bundle(bundle)
        assert "environment.egress: egress is 'enabled'; expected 'disabled' or a justification" in warnings

    def test_unsafe_companion_path_is_rejected(self, tmp_path):
        bundle = make_bundle(tmp_path, exploit__harness="../poc.py")
        with pytest.raises(BundleError, match="must be a relative path inside the bundle"):
            load_bundle(bundle)

    def test_missing_document(self, tmp_path):
        with pytest.raises(BundleError, match="not found"):
            load_bundle(tmp_path)

    def test_invalid_json(self, tmp_path):
        (tmp_path / BUNDLE_FILE).write_text("{not json")
        with pytest.raises(BundleError, match="not valid JSON"):
            load_bundle(tmp_path)

    def test_schema_errors_are_raised(self, tmp_path):
        bundle = make_bundle(tmp_path)
        doc = json.loads((bundle / BUNDLE_FILE).read_text())
        doc["verdict"] = "maybe"
        (bundle / BUNDLE_FILE).write_text(json.dumps(doc))
        with pytest.raises(BundleError, match="invalid bundle"):
            load_bundle(bundle)

    @pytest.mark.parametrize("name", ["poc.py", "trace.jsonl", "fix.diff", "actions.log"])
    def test_missing_companion_file(self, tmp_path, name):
        bundle = make_bundle(tmp_path)
        (bundle / name).unlink()
        with pytest.raises(BundleError, match=f"companion file '{name}' not found"):
            load_bundle(bundle)


# --------------------------------------------------------------------------- #
# Content addressing and signatures
# --------------------------------------------------------------------------- #


class TestDigest:
    def test_format_and_stability(self, tmp_path):
        bundle = make_bundle(tmp_path)
        d = compute_digest(bundle)
        assert d.startswith("sha256:") and len(d) == len("sha256:") + 64
        assert compute_digest(bundle) == d

    def test_independent_of_location(self, tmp_path):
        bundle = make_bundle(tmp_path)
        moved = shutil.copytree(bundle, tmp_path / "elsewhere" / "copy")
        assert compute_digest(moved) == compute_digest(bundle)

    def test_changes_when_document_changes(self, tmp_path):
        bundle = make_bundle(tmp_path)
        before = compute_digest(bundle)
        doc = json.loads((bundle / BUNDLE_FILE).read_text())
        doc["verdict"] = "not_reproduced"
        (bundle / BUNDLE_FILE).write_text(json.dumps(doc, indent=2))
        assert compute_digest(bundle) != before

    def test_changes_when_companion_changes(self, tmp_path):
        bundle = make_bundle(tmp_path)
        before = compute_digest(bundle)
        (bundle / "poc.py").write_text(HARNESS + "\n# tampered\n")
        assert compute_digest(bundle) != before

    def test_changes_when_file_added_or_renamed(self, tmp_path):
        bundle = make_bundle(tmp_path)
        before = compute_digest(bundle)
        (bundle / "extra.bin").write_bytes(b"x")
        added = compute_digest(bundle)
        (bundle / "extra.bin").rename(bundle / "other.bin")
        assert len({before, added, compute_digest(bundle)}) == 3

    def test_signature_file_is_excluded(self, tmp_path):
        bundle = make_bundle(tmp_path)
        before = compute_digest(bundle)
        (bundle / SIGNATURE_FILE).write_text("anything")
        assert compute_digest(bundle) == before

    def test_symlinks_are_rejected(self, tmp_path):
        bundle = make_bundle(tmp_path)
        (bundle / "link").symlink_to("/etc/hostname")
        with pytest.raises(BundleError, match="symlinks"):
            compute_digest(bundle)


class TestSignature:
    def test_roundtrip(self, keypair):
        private, public = keypair
        digest = "sha256:" + "ab" * 32
        verify_signature(digest, sign_digest(digest, private), public)

    def test_wrong_digest_fails(self, keypair):
        private, public = keypair
        sig = sign_digest("sha256:" + "ab" * 32, private)
        with pytest.raises(BundleError, match="does not match"):
            verify_signature("sha256:" + "cd" * 32, sig, public)

    def test_wrong_key_fails(self, keypair):
        private, _ = keypair
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = "sha256:" + "ab" * 32
        with pytest.raises(BundleError, match="does not match"):
            verify_signature(digest, sign_digest(digest, private), other)

    def test_garbage_signature_fails(self, keypair):
        _, public = keypair
        with pytest.raises(BundleError, match="does not match"):
            verify_signature("sha256:" + "ab" * 32, "!!not base64!!", public)

    def test_smoke_bundle_signature_verifies(self):
        sig = (SMOKE_BUNDLE / SIGNATURE_FILE).read_text()
        verify_signature(compute_digest(SMOKE_BUNDLE), sig, SMOKE_PUBKEY.read_bytes())


# --------------------------------------------------------------------------- #
# Oracle
# --------------------------------------------------------------------------- #


class TestOracle:
    def test_asan_signal_detected(self):
        assert evaluate_oracle({"kind": "asan", "signal": "heap-buffer-overflow"}, ASAN_REPORT)

    def test_asan_requires_matching_signal(self):
        assert not evaluate_oracle({"kind": "asan", "signal": "use-after-free"}, ASAN_REPORT)

    def test_asan_requires_report_header_not_just_the_word(self):
        out = "warning: possible heap-buffer-overflow in input\n"
        assert not evaluate_oracle({"kind": "asan", "signal": "heap-buffer-overflow"}, out)

    def test_asan_signal_is_not_a_prefix_match(self):
        out = "==1==ERROR: AddressSanitizer: heap-buffer-overflow-ish\n"
        assert not evaluate_oracle({"kind": "asan", "signal": "heap-buffer-overflow"}, out)

    def test_other_kinds_use_substring(self):
        assert evaluate_oracle({"kind": "custom", "signal": "PWNED"}, "x PWNED y")
        assert not evaluate_oracle({"kind": "custom", "signal": "PWNED"}, "clean")


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #


class TestReplay:
    def test_reproduced_matches(self, tmp_path):
        report = replay.replay(make_bundle(tmp_path), backend=LocalBackend())
        assert report.observed_verdicts == ["reproduced"] * 3
        assert report.matched and report.deterministic
        assert report.signature == "not_checked"

    def test_not_reproduced_matches(self, tmp_path):
        bundle = make_bundle(tmp_path, mode="ok", verdict="not_reproduced")
        report = replay.replay(bundle, backend=LocalBackend())
        assert report.observed_verdict == "not_reproduced"
        assert report.matched

    def test_claimed_reproduced_but_oracle_silent_is_a_mismatch(self, tmp_path):
        bundle = make_bundle(tmp_path, mode="ok", verdict="reproduced")
        report = replay.replay(bundle, backend=LocalBackend())
        assert not report.matched
        assert report.observed_verdict == "not_reproduced"

    def test_seed_is_passed_to_harness(self, tmp_path):
        bundle = make_bundle(tmp_path, mode="seed", replay__seed=42)
        assert replay.replay(bundle, backend=LocalBackend(), runs=1).matched
        other = make_bundle(tmp_path / "b", mode="seed", replay__seed=7)
        assert not replay.replay(other, backend=LocalBackend(), runs=1).matched

    def test_default_runs_follow_deterministic_flag(self, tmp_path):
        bundle = make_bundle(tmp_path, replay__deterministic=False)
        assert len(replay.replay(bundle, backend=LocalBackend()).observed_verdicts) == 1

    def test_explicit_runs(self, tmp_path):
        report = replay.replay(make_bundle(tmp_path), backend=LocalBackend(), runs=2)
        assert len(report.observed_verdicts) == 2

    def test_invalid_runs(self, tmp_path):
        with pytest.raises(ValueError):
            replay.replay(make_bundle(tmp_path), backend=LocalBackend(), runs=0)

    def test_nondeterministic_runs_do_not_match(self, tmp_path):
        outputs = iter([ASAN_REPORT, "clean exit\n"])

        class FlakyBackend:
            name = "flaky"
            isolated = True

            def run(self, workdir, argv, env, timeout):
                return replay.RunResult(returncode=0, output=next(outputs))

        report = replay.replay(make_bundle(tmp_path), backend=FlakyBackend(), runs=2)
        assert report.observed_verdicts == ["reproduced", "not_reproduced"]
        assert not report.deterministic
        assert report.observed_verdict is None
        assert not report.matched

    def test_harness_cannot_modify_bundle(self, tmp_path):
        bundle = make_bundle(tmp_path)
        (bundle / "poc.py").write_text(
            "import os; open('input.txt','w').write('changed'); "
            "os.makedirs('__pycache__', exist_ok=True)\n" + HARNESS
        )
        before = compute_digest(bundle)
        replay.replay(bundle, backend=LocalBackend(), runs=1)
        assert compute_digest(bundle) == before
        assert not (bundle / "__pycache__").exists()

    def test_harness_does_not_inherit_parent_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SECRET_TOKEN", "hunter2")
        bundle = make_bundle(tmp_path)
        (bundle / "poc.py").write_text(
            "import os, sys\n"
            "if 'SECRET_TOKEN' in os.environ:\n"
            "    sys.stderr.write('==1==ERROR: AddressSanitizer: heap-buffer-overflow\\n')\n"
        )
        report = replay.replay(bundle, backend=LocalBackend(), runs=1)
        assert report.observed_verdict == "not_reproduced"

    def test_timeout_is_reported(self, tmp_path):
        bundle = make_bundle(tmp_path, mode="sleep", verdict="not_reproduced")
        report = replay.replay(bundle, backend=LocalBackend(), runs=1, timeout=0.5)
        assert report.observed_verdict == "not_reproduced"
        assert any("timed out" in w for w in report.warnings)

    def test_warns_about_unisolated_backend_and_egress(self, tmp_path):
        bundle = make_bundle(tmp_path, environment__egress="enabled")
        warnings = replay.replay(bundle, backend=LocalBackend(), runs=1).warnings
        assert any("no isolation" in w for w in warnings)
        assert any("egress 'enabled'" in w for w in warnings)

    def test_expected_digest_mismatch(self, tmp_path):
        bundle = make_bundle(tmp_path)
        with pytest.raises(BundleError, match="digest mismatch"):
            replay.replay(bundle, backend=LocalBackend(), expected_digest="sha256:" + "0" * 64)

    def test_expected_digest_match(self, tmp_path):
        bundle = make_bundle(tmp_path)
        report = replay.replay(
            bundle, backend=LocalBackend(), expected_digest=compute_digest(bundle), runs=1
        )
        assert report.matched

    def test_signed_bundle_verifies(self, tmp_path, keypair):
        private, public = keypair
        bundle = make_bundle(tmp_path)
        sign(bundle, private)
        report = replay.replay(bundle, backend=LocalBackend(), public_key_pem=public, runs=1)
        assert report.signature == "verified"

    def test_tampered_signed_bundle_is_rejected_before_running(self, tmp_path, keypair):
        private, public = keypair
        bundle = make_bundle(tmp_path)
        sign(bundle, private)
        (bundle / "poc.py").write_text("open('ran', 'w').close()\n")
        with pytest.raises(BundleError, match="does not match"):
            replay.replay(bundle, backend=LocalBackend(), public_key_pem=public)

    def test_missing_signature_with_pubkey_is_rejected(self, tmp_path, keypair):
        _, public = keypair
        with pytest.raises(BundleError, match="not found"):
            replay.replay(make_bundle(tmp_path), backend=LocalBackend(), public_key_pem=public)

    def test_backend_is_pluggable(self, tmp_path):
        calls = []

        class FakeBackend:
            name = "fake"
            isolated = True

            def run(self, workdir, argv, env, timeout):
                calls.append((argv[-1], env["SHARUR_REPLAY_SEED"]))
                return replay.RunResult(returncode=1, output=ASAN_REPORT)

        report = replay.replay(make_bundle(tmp_path), backend=FakeBackend(), runs=1)
        assert report.matched and report.backend == "fake"
        assert calls == [("input.txt", "42")]
        assert not any("isolation" in w for w in report.warnings)

    def test_smoke_bundle_replays(self):
        report = replay.replay(
            SMOKE_BUNDLE, backend=LocalBackend(), public_key_pem=SMOKE_PUBKEY.read_bytes()
        )
        assert report.matched and report.signature == "verified"
        assert report.observed_verdicts == ["reproduced"] * 3


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


class TestCLI:
    def test_local_backend_requires_opt_in(self, tmp_path, capsys):
        assert replay.main(["replay", str(make_bundle(tmp_path))]) == 2
        assert "--unsafe-local" in capsys.readouterr().err

    def test_replay_match_exit_zero_and_json_report(self, tmp_path, capsys):
        rc = replay.main(["replay", str(make_bundle(tmp_path)), "--unsafe-local", "--runs", "1"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out["matched"] is True and out["observed_verdict"] == "reproduced"

    def test_replay_mismatch_exit_one(self, tmp_path, capsys):
        bundle = make_bundle(tmp_path, mode="ok")
        assert replay.main(["replay", str(bundle), "--unsafe-local", "--runs", "1"]) == 1

    def test_replay_invalid_exit_two(self, tmp_path, capsys):
        assert replay.main(["replay", str(tmp_path), "--unsafe-local"]) == 2

    def test_sign_then_replay_with_pubkey(self, tmp_path, keypair, capsys):
        private, public = keypair
        bundle = make_bundle(tmp_path)
        (tmp_path / "k.pem").write_bytes(private)
        (tmp_path / "k.pub").write_bytes(public)
        assert replay.main(["sign", str(bundle), "--key", str(tmp_path / "k.pem")]) == 0
        args = ["replay", str(bundle), "--unsafe-local", "--runs", "1", "--pubkey", str(tmp_path / "k.pub")]
        assert replay.main(args) == 0
        (bundle / "input.txt").write_text("ok")
        assert replay.main(args) == 2

    def test_digest(self, tmp_path, capsys):
        bundle = make_bundle(tmp_path)
        assert replay.main(["digest", str(bundle)]) == 0
        assert capsys.readouterr().out.strip() == compute_digest(bundle)

    def test_missing_key_file_is_a_clean_error(self, tmp_path, capsys):
        args = ["replay", str(make_bundle(tmp_path)), "--unsafe-local", "--pubkey", str(tmp_path / "nope")]
        assert replay.main(args) == 2
        assert capsys.readouterr().err.startswith("error:")

    def test_malformed_key_is_a_clean_error(self, tmp_path, capsys):
        (tmp_path / "bad.pem").write_text("not a key")
        args = ["replay", str(make_bundle(tmp_path)), "--unsafe-local", "--pubkey", str(tmp_path / "bad.pem")]
        assert replay.main(args) == 2
        assert capsys.readouterr().err.startswith("error:")
