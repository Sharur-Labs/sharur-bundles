"""Reference replayer for Sharur bundles.

A Sharur bundle is a directory holding ``sharur-bundle.json`` plus the companion
files it references (harness, trace, patch, action log). This module lets a
third party, without access to the engine that produced the bundle:

1. **verify** the document's shape against the spec, using :mod:`verify`,
2. **content-address** the bundle: compute a digest over every file in it,
3. **check** a detached Ed25519 signature over that digest,
4. **replay** the exploit with the recorded seed, evaluate the oracle, and check
   that the observed verdict matches the recorded one.

It has no dependency on the proprietary engine. The only third-party
dependency is ``cryptography``, used for signatures.

Exit codes for the CLI:
    0  replay matched the recorded verdict
    1  replay ran but the verdict did not match, or runs disagreed
    2  the bundle is invalid, tampered with, or its signature did not verify
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from verify import BUNDLE_FILE, verify_bundle

__all__ = [
    "BUNDLE_FILE",
    "SIGNATURE_FILE",
    "BundleError",
    "LocalBackend",
    "ReplayReport",
    "RunResult",
    "compute_digest",
    "evaluate_oracle",
    "load_bundle",
    "main",
    "replay",
    "sign_digest",
    "verify_signature",
]

SIGNATURE_FILE = "sharur-bundle.sig"

# Prefix mixed into every signed message so a signature over a bundle digest
# cannot be confused with a signature produced for some other purpose.
SIGNATURE_DOMAIN = b"sharur-bundle-digest-v0:"


class BundleError(Exception):
    """The bundle is malformed, tampered with, or failed signature checks."""


# --------------------------------------------------------------------------- #
# Content addressing and signatures
# --------------------------------------------------------------------------- #


def _bundle_files(bundle_dir: Path) -> list[Path]:
    files = []
    for p in sorted(bundle_dir.rglob("*")):
        if p.is_symlink():
            raise BundleError(f"symlinks are not allowed in a bundle: {p.relative_to(bundle_dir)}")
        if p.is_file() and p.relative_to(bundle_dir).as_posix() != SIGNATURE_FILE:
            files.append(p)
    return files


def compute_digest(bundle_dir: Path) -> str:
    """Return the content address of a bundle directory.

    The digest is ``sha256`` over a manifest with one line per file,
    ``<sha256 hex>  <posix relative path>\\n``, sorted by path. Every file in the
    directory is covered except the detached signature, so changing, adding or
    removing any file changes the digest.
    """
    manifest = []
    for p in _bundle_files(bundle_dir):
        rel = p.relative_to(bundle_dir).as_posix()
        manifest.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}\n")
    manifest.sort(key=lambda line: line.split("  ", 1)[1])
    return "sha256:" + hashlib.sha256("".join(manifest).encode()).hexdigest()


def sign_digest(digest: str, private_key_pem: bytes) -> str:
    """Sign a bundle digest with an Ed25519 private key. Returns base64 text."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleError("signing key must be an Ed25519 private key")
    return base64.b64encode(key.sign(SIGNATURE_DOMAIN + digest.encode())).decode()


def verify_signature(digest: str, signature_b64: str, public_key_pem: bytes) -> None:
    """Raise :class:`BundleError` unless ``signature_b64`` signs ``digest``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise BundleError("public key must be an Ed25519 key")
    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
        key.verify(sig, SIGNATURE_DOMAIN + digest.encode())
    except (InvalidSignature, ValueError) as exc:
        raise BundleError("signature does not match bundle contents") from exc


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def load_bundle(bundle_dir: Path) -> tuple[dict[str, Any], list[str]]:
    """Load a bundle directory and verify its shape. Returns ``(doc, warnings)``.

    Raises :class:`BundleError` if the bundle does not conform to the spec.
    Spec warnings (see :mod:`verify`) are returned, not raised.
    """
    bundle_dir = Path(bundle_dir)
    if not (bundle_dir / BUNDLE_FILE).is_file():
        raise BundleError(f"{bundle_dir / BUNDLE_FILE} not found")
    report = verify_bundle(bundle_dir)
    if report.errors:
        raise BundleError("invalid bundle:\n  " + "\n  ".join(str(e) for e in report.errors))
    doc = json.loads((bundle_dir / BUNDLE_FILE).read_text(encoding="utf-8"))
    return doc, [str(w) for w in report.warnings]


# --------------------------------------------------------------------------- #
# Oracle
# --------------------------------------------------------------------------- #


def evaluate_oracle(oracle: dict[str, Any], output: str) -> bool:
    """Return True if ``output`` shows the oracle's signal firing.

    ``asan`` oracles match the AddressSanitizer report header
    (``ERROR: AddressSanitizer: <signal>``). Any other kind falls back to a
    plain substring match on ``oracle.signal``.
    """
    signal = oracle["signal"]
    if oracle["kind"] == "asan":
        # ASan signal names contain hyphens, so \b would let "heap-buffer-overflow"
        # match "heap-buffer-overflow-foo"; require the name to end here.
        pattern = rf"ERROR: AddressSanitizer: {re.escape(signal)}(?![\w-])"
        return re.search(pattern, output) is not None
    return signal in output


# --------------------------------------------------------------------------- #
# Execution backends
# --------------------------------------------------------------------------- #


@dataclass
class RunResult:
    returncode: int | None
    output: str
    timed_out: bool = False


class Backend(Protocol):
    name: str
    isolated: bool

    def run(self, workdir: Path, argv: list[str], env: dict[str, str], timeout: float) -> RunResult: ...


class LocalBackend:
    """Runs the harness as a plain subprocess on this machine.

    This provides **no isolation and no egress control**. It exists for testing
    and for bundles you already trust; a replay of an untrusted bundle belongs
    in a microVM backend.
    """

    name = "local"
    isolated = False

    def run(self, workdir: Path, argv: list[str], env: dict[str, str], timeout: float) -> RunResult:
        try:
            proc = subprocess.run(
                argv,
                cwd=workdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.output.decode(errors="replace") if exc.output else ""
            return RunResult(returncode=None, output=out, timed_out=True)
        return RunResult(returncode=proc.returncode, output=proc.stdout.decode(errors="replace"))


def _harness_argv(harness: Path, inputs: list[str]) -> list[str]:
    if harness.suffix == ".py":
        return [sys.executable, str(harness), *inputs]
    return [str(harness), *inputs]


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #


@dataclass
class ReplayReport:
    finding_id: str
    digest: str
    signature: str  # "verified" | "not_checked"
    backend: str
    expected_verdict: str
    observed_verdicts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def deterministic(self) -> bool:
        return len(set(self.observed_verdicts)) == 1

    @property
    def observed_verdict(self) -> str | None:
        return self.observed_verdicts[0] if self.deterministic else None

    @property
    def matched(self) -> bool:
        return self.observed_verdict == self.expected_verdict

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.update(
            observed_verdict=self.observed_verdict,
            deterministic=self.deterministic,
            matched=self.matched,
        )
        return d


def replay(
    bundle_dir: Path,
    *,
    backend: Backend,
    public_key_pem: bytes | None = None,
    expected_digest: str | None = None,
    runs: int | None = None,
    timeout: float = 60.0,
) -> ReplayReport:
    """Verify and replay a bundle.

    Raises :class:`BundleError` if the bundle is invalid, its digest differs
    from ``expected_digest``, or ``public_key_pem`` is given and the signature
    is missing or wrong. Otherwise runs the harness ``runs`` times (default: 3
    if the bundle claims to be deterministic, else 1) and returns a report.
    """
    bundle_dir = Path(bundle_dir)
    doc, warnings = load_bundle(bundle_dir)
    digest = compute_digest(bundle_dir)

    if expected_digest is not None and digest != expected_digest:
        raise BundleError(f"digest mismatch: bundle is {digest}, expected {expected_digest}")

    signature = "not_checked"
    if public_key_pem is not None:
        sig_path = bundle_dir / SIGNATURE_FILE
        if not sig_path.is_file():
            raise BundleError(f"{SIGNATURE_FILE} not found but a public key was given")
        verify_signature(digest, sig_path.read_text(), public_key_pem)
        signature = "verified"

    if not backend.isolated:
        warnings.append(f"backend {backend.name!r} provides no isolation or egress control")
    if doc["environment"]["egress"] != "disabled":
        warnings.append(f"bundle was recorded with egress {doc['environment']['egress']!r}")

    if runs is None:
        runs = 3 if doc["replay"]["deterministic"] else 1
    if runs < 1:
        raise ValueError("runs must be >= 1")

    report = ReplayReport(
        finding_id=doc["finding_id"],
        digest=digest,
        signature=signature,
        backend=backend.name,
        expected_verdict=doc["verdict"],
        warnings=warnings,
    )

    seed = str(doc["replay"]["seed"])
    for _ in range(runs):
        # Run each attempt in a fresh copy so the harness can neither alter the
        # bundle on disk nor see state left behind by an earlier run.
        with tempfile.TemporaryDirectory(prefix="sharur-replay-") as tmp:
            workdir = Path(tmp) / "bundle"
            shutil.copytree(bundle_dir, workdir, symlinks=True)
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": tmp,
                "TMPDIR": tmp,
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": seed,
                "SHARUR_REPLAY_SEED": seed,
            }
            argv = _harness_argv(workdir / doc["exploit"]["harness"], doc["exploit"]["inputs"])
            result = backend.run(workdir, argv, env, timeout)
        if result.timed_out:
            report.warnings.append(f"run {len(report.observed_verdicts) + 1} timed out after {timeout}s")
        fired = evaluate_oracle(doc["oracle"], result.output)
        report.observed_verdicts.append("reproduced" if fired else "not_reproduced")

    return report


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _cmd_replay(args: argparse.Namespace) -> int:
    if args.backend == "local" and not args.unsafe_local:
        raise BundleError(
            "the local backend runs the bundle's harness on this machine with no "
            "isolation. Pass --unsafe-local to confirm you trust this bundle."
        )
    report = replay(
        Path(args.bundle),
        backend=LocalBackend(),
        public_key_pem=Path(args.pubkey).read_bytes() if args.pubkey else None,
        expected_digest=args.expect_digest,
        runs=args.runs,
        timeout=args.timeout,
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.matched else 1


def _cmd_digest(args: argparse.Namespace) -> int:
    print(compute_digest(Path(args.bundle)))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    load_bundle(bundle)
    sig = sign_digest(compute_digest(bundle), Path(args.key).read_bytes())
    (bundle / SIGNATURE_FILE).write_text(sig + "\n")
    print(f"wrote {bundle / SIGNATURE_FILE}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sharur-replay", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("replay", help="verify a bundle and re-run its exploit")
    p.add_argument("bundle", help="path to the bundle directory")
    p.add_argument("--backend", choices=["local"], default="local")
    p.add_argument("--unsafe-local", action="store_true", help="allow the unisolated local backend")
    p.add_argument("--pubkey", help="Ed25519 public key (PEM); requires a valid signature")
    p.add_argument("--expect-digest", help="fail unless the bundle has this content digest")
    p.add_argument("--runs", type=int, help="number of replays (default: 3 if deterministic, else 1)")
    p.add_argument("--timeout", type=float, default=60.0, help="seconds per run (default: 60)")
    p.set_defaults(func=_cmd_replay)

    p = sub.add_parser("digest", help="print a bundle's content digest")
    p.add_argument("bundle")
    p.set_defaults(func=_cmd_digest)

    p = sub.add_parser("sign", help="write a detached signature for a bundle")
    p.add_argument("bundle")
    p.add_argument("--key", required=True, help="Ed25519 private key (PEM)")
    p.set_defaults(func=_cmd_sign)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (BundleError, OSError, ValueError) as exc:
        # ValueError covers malformed PEM keys and invalid --runs values.
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
