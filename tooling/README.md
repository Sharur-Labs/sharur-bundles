# Sharur bundle reference tooling

Two standalone tools that let a third party check Sharur bundles without the
engine that produced them:

| Tool | What it does | Runs bundle code? | Dependencies |
| --- | --- | --- | --- |
| `sharur-verify` | Checks that a bundle conforms to the spec. | No | Standard library only |
| `sharur-replay` | Checks the bundle's digest and signature, re-runs the exploit, and compares the verdict. | Yes | `cryptography` |

```bash
pip install ./tooling

sharur-verify path/to/bundle                   # does it conform to the spec?
sharur-verify --strict path/to/bundle          # ...and follow DOCS.md conventions?
sharur-replay digest path/to/bundle            # print the content address
sharur-replay replay path/to/bundle --unsafe-local --pubkey signer.pub.pem
```

## sharur-verify

`sharur-verify` checks a bundle against the open spec (`../sharur-bundle-spec.yaml`)
without executing anything in it, so it's safe to run on untrusted bundles.
Point it at a bundle directory or straight at a JSON file. It accepts several
paths at once.

```
$ sharur-verify --skip-files ../sharur-bundle.json
../sharur-bundle.json: valid (0 error(s), 10 warning(s))
  warning[placeholder] source.original_id: '...' looks empty or like a placeholder
  warning[format] target.commit: 'a1b2c3' is not a full lowercase commit hash (40 or 64 hex)
  ...
```

Each issue has a level, a stable code, and the dotted path of the field it's
about. `--format json` emits the same issues as machine-readable output.

**Errors.** The bundle doesn't conform to the spec.

| Code | Meaning |
| --- | --- |
| `json` | Not valid JSON, not UTF-8, or uses `NaN`/`Infinity`. |
| `duplicate-key` | An object repeats a key, so different readers may see different values. |
| `missing` | A field the spec defines is absent. Every field is required, because the spec doesn't mark any as optional yet. |
| `type` | Wrong type. `true` is not an integer and `1` is not a boolean. |
| `enum` | `severity` or `verdict` is not an allowed value, for example the first-draft spellings `High` or `Not Reproduced`. |
| `path` | A companion path is absolute, contains `..` or a backslash, or has a drive letter. |
| `file-missing` | A referenced companion file doesn't exist. `--skip-files` turns this check off. |

**Warnings.** Recommendations in DOCS.md that the spec doesn't require yet.
`--strict` treats them as errors.

| Code | Meaning |
| --- | --- |
| `unknown-field` | A field the spec doesn't define. |
| `format` | `target.commit` isn't a full 40- or 64-character hex hash, `image_digest` isn't `<algorithm>:<hex>`, `audit.started` isn't an ISO 8601 UTC timestamp, or `exploit.steps` is less than 1. |
| `placeholder` | A value is empty or still contains `...`. |
| `egress` | `environment.egress` is something other than `disabled`. |

Exit codes: `0` every bundle conforms, `1` at least one doesn't, `2` a path
couldn't be read.

### Conformance fixtures

`tests/smoke/conformance/` holds a fixture for each error and warning. Each one
is a copy of the clean sample with a single defect. `expected.json` lists the
exact `[code, path]` pairs a conforming verifier must report for each fixture.
The unit tests and the smoke test both check against it. Another implementation
of the spec can reuse the fixtures to test itself.

## sharur-replay

`replay` prints a JSON report and exits `0` if every run reproduced the
recorded verdict, `1` if the runs produced a different verdict or disagreed
with each other, and `2` if the bundle is invalid, its digest or signature
didn't check out, or the arguments were wrong.

1. **Verify the shape.** Runs `sharur-verify`'s checks. Errors stop the replay;
   warnings go into the report.
2. **Content-address.** Computes the bundle digest. With `--expect-digest`, the
   replay fails unless the digest matches.
3. **Verify the signature.** With `--pubkey`, `sharur-bundle.sig` must be a valid
   Ed25519 signature over the digest. This check runs before any bundle code.
4. **Re-run.** Copies the bundle into a fresh temporary directory and runs
   `exploit.harness` with `exploit.inputs` as arguments. It runs 3 times if
   `replay.deterministic` is true, otherwise once (`--runs` overrides).
5. **Evaluate the oracle.** For `asan`, a run counts as `reproduced` if its
   output contains `ERROR: AddressSanitizer: <oracle.signal>`. For any other
   kind, it counts if `oracle.signal` appears anywhere in the output.
6. **Compare.** The replay passes if every run agrees with the recorded
   `verdict`.

### Conventions the replayer assumes

The spec doesn't define these yet. They are candidates for adding to it.

- **Harness invocation.** A harness ending in `.py` runs as
  `python <harness> <inputs...>`; anything else is executed directly. The
  working directory is the copy of the bundle.
- **Seed and environment.** `replay.seed` is passed as `SHARUR_REPLAY_SEED` (and
  `PYTHONHASHSEED`). The harness gets only `PATH`, `HOME`, `TMPDIR`, `LANG` and
  the seed variables. Nothing else is inherited from the caller.
- **Digest.** `sha256` over a manifest with one line per file in the bundle
  directory, `<sha256 hex>  <relative posix path>\n`, sorted by path. Every file
  is covered except `sharur-bundle.sig`. Symlinks are rejected.
- **Signature.** `sharur-bundle.sig` holds a base64 Ed25519 signature over the
  bytes `sharur-bundle-digest-v0:` followed by the digest string. Create one with
  `sharur-replay sign <bundle> --key <private.pem>`.

### Limitations

- **Only a local backend exists, and it has no isolation.** It runs the harness
  as an ordinary subprocess, with network access. Use it only for bundles you
  trust, which is why it requires `--unsafe-local`. `Backend` in
  `src/replay.py` is the interface a microVM backend would implement.
- **The target isn't rebuilt.** `target.repo`, `commit` and `build` aren't used.
  The smoke sample vendors its target inside the bundle.
- **Fix verification isn't done.** The `fix.*` fields are verified and covered
  by the digest, but the patch isn't applied.
- **No `spec_version`.** The spec has no version field yet, so both tools target
  the current draft. A `spec_version` field currently shows up as an
  `unknown-field` warning.

## Development

```bash
cd tooling
python -m pip install -e '.[test]'
python -m pytest            # unit tests for both tools
tests/smoke/verify.sh       # sharur-verify against the sample and conformance fixtures (needs jq)
tests/smoke/replay.sh       # sharur-replay against the sample bundle
```

The schema embedded in `src/verify.py` must stay identical to
`../sharur-bundle-spec.yaml`, and a unit test fails if they drift apart. When
the spec changes, update the YAML, `SCHEMA`, the sample bundle and the
conformance fixtures together.

### The smoke sample

`tests/smoke/pcf-2026-0001/` is a hand-made bundle with a simulated
heap-buffer-overflow target written in pure Python, so it runs anywhere without
a compiler. It's signed by `tests/smoke/keys/sample-signer.pub.pem`. The
matching private key was not kept, so any edit to the sample breaks its
signature by design. To change the sample, generate a new Ed25519 keypair, run
`sharur-replay sign tests/smoke/pcf-2026-0001 --key new.pem`, and replace the
public key. Don't commit the private key.
