# Sharur Bundle Documentation

This guide explains how to read, produce and review a Sharur bundle. For a short
overview of the repo, see [`README.md`](README.md).

**Sources of truth**

- [`sharur-bundle-spec.yaml`](sharur-bundle-spec.yaml): **the spec.** It defines every
  field name, its type and the allowed enum values. It does not contain real
  values: `string`, `integer` and `boolean` stand for *a value of that type*.
- [`sharur-bundle.json`](sharur-bundle.json): **an example**, showing one way to
  write a bundle as JSON. Its `...` placeholders mean "some string goes here".
  They are not values defined by the spec.

If the two ever disagree, the YAML wins and the example should be fixed. The
spec does not currently contain prose definitions, so the descriptions of what
each field *means* in this guide are interpretations of the field names and the
example values.

## Contents

1. [Concepts](#1-concepts)
2. [Anatomy of a bundle](#2-anatomy-of-a-bundle)
3. [Field reference](#3-field-reference)
4. [Producing a bundle](#4-producing-a-bundle)
5. [Reviewing a bundle](#5-reviewing-a-bundle)
6. [Validating a bundle](#6-validating-a-bundle)
7. [Suggested companion files](#7-suggested-companion-files)
8. [Changes from earlier drafts and open questions](#8-changes-from-earlier-drafts-and-open-questions)
9. [FAQ](#9-faq)

---

## 1. Concepts

**Finding.** A claim, usually from an automated tool, that a target contains a
vulnerability. The tool that reported it is recorded in `source`.

**Engine.** The (closed-source) agentic reproduction system that attempts to
reproduce a finding and emits a Sharur bundle with the outcome. It is not part of
this repo. This guide describes what it emits, not how it works internally.

**Producer and consumer.** The engine is the producer. Consumers are the people
and tools that read bundles: security reviewers, triage and ticketing systems,
maintainers receiving a disclosure, and auditors.

**Sharur bundle.** One JSON document, plus any files it references, that lets a
third party confirm or refute a finding without trusting the tool that reported
it.

**Oracle.** An objective, machine-observable signal that the bug triggered, such
as an AddressSanitizer `heap-buffer-overflow` report. The oracle is what
separates a reproduced finding from a plausible-looking one.

**Verdict.** The outcome: `reproduced` or `not_reproduced`.

A bundle is useful when each section supports the verdict. A `reproduced`
verdict with no oracle output, or an exploit that ran with network access, is a
weak bundle even if every field is present.

## 2. Anatomy of a bundle

The example bundle (`sharur-bundle.json`) has this shape. A `"..."` stands for
any string; real bundles contain real values.

```json
{
  "finding_id": "pcf-2026-0001",
  "source":       { "tool": "...", "original_id": "...", "class": "CWE-787" },
  "target":       { "repo": "...", "commit": "...", "build": { "recipe": "...", "image_digest": "..." } },
  "environment":  { "microvm": "...", "kernel": "...", "egress": "disabled" },
  "exploit":      { "harness": "poc.py", "inputs": ["..."], "steps": 12 },
  "oracle":       { "kind": "asan", "signal": "heap-buffer-overflow", "minimal_effect": true, "observed": "..." },
  "replay":       { "seed": 42, "deterministic": true, "trace": "trace.jsonl" },
  "reachability": { "exposed": true, "entrypoint": "HTTP /upload", "severity": "high" },
  "dedup":        { "root_cause_hash": "...", "cluster": "pcf-2026-0001" },
  "fix":          { "patch": "fix.diff", "poc_now_fails": true, "tests_pass": true },
  "audit":        { "scope_signed_by": "...", "started": "...", "actions": "actions.log" },
  "verdict": "reproduced"
}
```

Several fields hold **paths to companion files** (`exploit.harness`,
`replay.trace`, `fix.patch`, `audit.actions`). A bundle is therefore a JSON
document plus those files. See [section 7](#7-suggested-companion-files).

## 3. Field reference

Names and types below come from the spec (`sharur-bundle-spec.yaml`). "Example" is
taken from the example bundle and is only illustrative.

### 3.1 Identity

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `finding_id` | string | Unique ID for this finding within your system. The example uses `pcf-<year>-<serial>`. | `pcf-2026-0001` |

### 3.2 `source`: where the finding came from

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `source.tool` | string | The tool or person that reported the finding. | `codex-security` |
| `source.original_id` | string | The finding's ID in the reporting tool, so you can trace back to the original report. | `...` |
| `source.class` | string | Vulnerability class. The example uses a CWE identifier. | `CWE-787` |

### 3.3 `target` and `build`: what was tested

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `target.repo` | string | Git URL of the code under test. | `git@...` |
| `target.commit` | string | Commit that was tested. Use the full hash so the reference is unambiguous. | `a1b2c3` |
| `build.recipe` | string | How the target was built. The example uses a Nix reference. | `nix:...` |
| `build.image_digest` | string | Content digest of the built image, which pins the exact binary environment. | `sha256:...` |

`build` is nested inside `target`: it describes how that target was built.

### 3.4 `environment`: where the exploit ran

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `environment.microvm` | string | The microVM and version used for isolation. | `fc-v1.9` |
| `environment.kernel` | string | Guest kernel version. A string, so versions like `6.1.2` are representable. | `6.x` |
| `environment.egress` | string | The guest's network egress setting. The example uses `disabled`. The spec does not enumerate other values. | `disabled` |

The default posture is **egress off**. If a bundle's environment allowed network
access, a reviewer should treat the result with more suspicion and expect a
justification.

### 3.5 `exploit`: what was run

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `exploit.harness` | string | Path to the script or program that triggers the bug. | `poc.py` |
| `exploit.inputs` | list of strings | The inputs the harness consumes. | `["..."]` |
| `exploit.steps` | integer | Number of steps in the exploit. | `12` |

### 3.6 `oracle`: how the effect was confirmed

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `oracle.kind` | string | The detector or oracle type. | `asan` |
| `oracle.signal` | string | The specific signal it raised. | `heap-buffer-overflow` |
| `oracle.minimal_effect` | boolean | `true` if the exploit demonstrated only the smallest effect needed to prove the bug, with no payload beyond that. | `true` |
| `oracle.observed` | string | The raw oracle output (or an excerpt) captured during the run. | `WRITE of size 8 at 0x...` |

`oracle.signal` should match what the `source.class` predicts. In the example,
`CWE-787` (out-of-bounds write) pairs with an ASan `heap-buffer-overflow` and a
`WRITE`.

### 3.7 `replay`: reproducing the result

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `replay.seed` | integer | RNG seed used for the recorded run. | `42` |
| `replay.deterministic` | boolean | `true` if repeated replays with this seed produced the same oracle result. | `true` |
| `replay.trace` | string | Path to the recorded execution trace. The example uses JSON Lines. | `trace.jsonl` |

### 3.8 `reachability`: does it matter in practice

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `reachability.exposed` | boolean | `true` if the vulnerable code can be reached from an attacker-controlled entrypoint. | `true` |
| `reachability.entrypoint` | string | The entrypoint, such as a route, port or API. | `HTTP /upload` |
| `reachability.severity` | enum | One of `informational`, `low`, `medium`, `high`. | `high` |

### 3.9 `dedup`: grouping findings by root cause

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `dedup.root_cause_hash` | string | Stable hash identifying the underlying defect, so reports of the same bug collide. | `...` |
| `dedup.cluster` | string | ID of the cluster this finding belongs to. | `pcf-2026-0001` |

In the example, the cluster ID equals the finding's own ID. That is natural for
the first finding in a cluster, which then acts as its canonical member.

### 3.10 `fix`: the remediation

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `fix.patch` | string | Path to a diff that fixes the issue. | `fix.diff` |
| `fix.poc_now_fails` | boolean | `true` if the exploit no longer triggers the oracle with the patch applied. | `true` |
| `fix.tests_pass` | boolean | `true` if the project's existing tests still pass with the patch applied. | `true` |

### 3.11 `audit`: authorisation and accountability

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `audit.scope_signed_by` | string | Who signed off on the testing scope, meaning who authorised testing this target. | `...` |
| `audit.started` | string | When the work began. Use an ISO 8601 UTC timestamp. | `...` |
| `audit.actions` | string | Path to a log of every action taken during testing. | `actions.log` |

### 3.12 `verdict`

| Value | Meaning |
| --- | --- |
| `reproduced` | The exploit triggered the oracle in the recorded environment. |
| `not_reproduced` | It did not. |

`verdict` is a single enum value at the top level of the bundle, not an object.

## 4. Producing a bundle

Bundles are normally produced by the reproduction engine, not written by hand.
This section lists what a producer, whether that is the engine or anyone else who
emits bundles, has to establish for each section to be trustworthy. It is a
contract for the output, not a description of the engine's internals. The steps
read as a manual procedure, so a person can follow them to build or hand-check a
bundle.

1. **Pin the target.** Record `target.repo` and the full `target.commit`. Build it
   reproducibly and record the `build.recipe` and the resulting
   `build.image_digest`.
2. **Get authorisation.** Before testing anything you do not own, have the scope
   signed, and record the signer in `audit.scope_signed_by`. Start the action log
   and set `audit.started`.
3. **Isolate.** Run the exploit inside a microVM with network egress disabled.
   Record the microVM version, kernel and egress setting in `environment`.
4. **Run the exploit.** Keep the harness and its inputs. Set `exploit.harness`
   and `exploit.inputs`.
5. **Capture the oracle.** Save the raw output into `oracle.observed` and fill in
   `kind` and `signal`. Keep the effect minimal and set `minimal_effect`
   accordingly.
6. **Make it replayable.** Fix the seed, record a trace, run the replay several
   times, and set `replay.deterministic` to `true` only if the results matched
   every time.
7. **Assess exposure.** Identify the entrypoint through which an attacker could
   reach the code, and set `exposed` and `severity` honestly. A reproduced crash
   that no attacker can reach is not high severity.
8. **Deduplicate.** Compute `dedup.root_cause_hash` and assign or join a cluster.
9. **Attempt a fix.** Write a patch, rerun the exploit against it, run the
   project's tests, and set `poc_now_fails` and `tests_pass` from the actual
   results.
10. **Decide the verdict.** `reproduced` only if step 5 produced the oracle signal
    and step 6 held up. Otherwise `not_reproduced`, and still keep the bundle, as
    a record that the claim was checked.
11. **Assemble.** Write the JSON and put the referenced files next to it
    ([section 7](#7-suggested-companion-files)).

## 5. Reviewing a bundle

Work through the sections in this order. Each check can fail independently.

| Check | What to look for |
| --- | --- |
| **Pinned?** | `commit` is a full hash and `image_digest` is present. Can you rebuild and get the same digest? |
| **Isolated?** | Egress is disabled. Anything else needs a stated reason. |
| **Oracle matches the claim?** | `oracle.signal` and `observed` fit `source.class`. A `CWE-787` finding backed by a null-pointer-dereference signal is a mismatch. |
| **Minimal?** | `minimal_effect` is `true` and the exploit does only what is needed to prove the bug. |
| **Replays?** | Re-run the harness with `replay.seed` and confirm you get the same oracle output. |
| **Reachable?** | `exposed` and `entrypoint` agree with the exploit, and severity is proportionate. |
| **Fix holds?** | Apply `fix.patch`, rerun the exploit, and confirm it no longer triggers. Run the tests. |
| **Authorised?** | `scope_signed_by` is a real, appropriate signer, and `actions.log` shows nothing outside the stated scope. |
| **Verdict follows?** | The verdict is consistent with everything above. |

Treat the booleans in `replay` and `fix` as claims, not proof. The point of the
bundle is that you can re-run them yourself.

## 6. Validating a bundle

There is no machine-checkable schema yet (see [section 8](#8-changes-from-earlier-drafts-and-open-questions)).
Until there is, this `jq` check confirms the required top-level sections are
present. It exits non-zero and names the missing sections if any are absent. It
does **not** check types, enums or nested fields.

```bash
jq -e 'def req: ["finding_id","source","target","environment","exploit","oracle",
                 "replay","reachability","dedup","fix","audit","verdict"];
       (req - keys) as $m
       | if ($m|length)==0 then "ok" else error("missing: \($m|join(","))") end' \
   path/to/sharur-bundle.json
```

To confirm that the files a bundle references exist alongside it:

```bash
dir=path/to/bundle
for f in $(jq -r '.exploit.harness, .replay.trace, .fix.patch, .audit.actions' "$dir/sharur-bundle.json"); do
  [ -e "$dir/$f" ] || echo "missing: $f"
done
```

## 7. Suggested companion files

The spec names these files but does not define a directory layout. This is a
suggested convention, not part of the spec:

```
pcf-2026-0001/
├── sharur-bundle.json   # the document described above
├── poc.py              # exploit.harness
├── trace.jsonl         # replay.trace
├── fix.diff            # fix.patch
└── actions.log         # audit.actions
```

Paths in the JSON should be relative to the bundle directory so the whole
directory can be moved, archived or shared as a unit.

## 8. Changes from earlier drafts and open questions

### Changes from the first draft of the spec

The first draft of `sharur-bundle-spec.yaml` did not match the JSON example, so
the YAML was updated to match it. If you have tooling or bundles written against
the first draft, migrate as follows:

| Area | First draft | Now |
| --- | --- | --- |
| Top-level wrapper | Everything under a `proof:` key | No wrapper: sections sit at the top level |
| `build` | Top-level section | Nested in `target` (`target.build`) |
| microVM version | `environment.microvm_ver` | `environment.microvm` |
| Kernel | `float` | `string` |
| Egress | `environment.egress_enable: boolean` | `environment.egress: string` |
| `exploit.inputs` | object (`{}`) | list of strings |
| `exploit.steps` | absent | `integer` |
| Cluster | `dedup.findings_cluster` | `dedup.cluster` |
| `severity` values | `Informational`, `Low`, `Medium`, `High` | `informational`, `low`, `medium`, `high` |
| `verdict` values | `Not Reproduced`, `Reproduced` | `not_reproduced`, `reproduced` |

Two of these are not purely cosmetic:

- `egress_enable: true` meant network access was **on**, whereas `egress: "disabled"`
  means it is **off**. Do not convert one to the other mechanically.
- The enum values are now lowercase, and the verdict uses `_` instead of a space
  (`not_reproduced`). Update any consumer that compares them as strings.

### Open questions

These are places where the spec is still underspecified. They need decisions
before it can be called stable.

- **Egress values.** `environment.egress` is a free-form string. Decide whether it
  should be an enum (for example `disabled` and some value for "enabled").
- **Required vs optional.** The spec does not say which fields are mandatory. For
  example, a `not_reproduced` bundle probably has no meaningful `fix`.
- **Severity scale.** There is no `Critical` level. Decide whether that is
  intentional.
- **Version field.** The bundle has no `spec_version`, so consumers cannot tell
  which revision they are reading.
- **Machine-checkable schema.** The YAML is a readable type description, not JSON
  Schema, and its enum syntax is not standard. A JSON Schema generated from it
  would allow automatic validation.
- **Formats.** Pin down the formats for `commit` (full hash), `started`
  (ISO 8601 UTC), `root_cause_hash` (algorithm and inputs), and the trace and
  action-log file formats.
- **Integrity.** `audit.scope_signed_by` names a signer but nothing is
  cryptographically bound to the bundle. Consider signing the bundle or
  recording file hashes.

## 9. FAQ

**Do I need the engine to use a bundle?**
No. A bundle is plain JSON plus ordinary files (a script, a trace, a diff, a log).
Reviewing it needs only the checks in [section 5](#5-reviewing-a-bundle) and the
tools to rebuild and run the target.

**Is the engine available, or can I run it myself?**
No. It is closed-source and not distributed through this repo. This repo only
defines the output format.

**Does a bundle reveal how the engine works?**
It records *what* was done and *what was observed*: the target, environment,
exploit, oracle output, trace and action log. The spec has no field for agent
prompts, model details or engine internals. If a producer chooses to put such
content in `audit.actions` or the trace, that is the producer's decision.

**Can I use this for a finding I could not reproduce?**
Yes. Set the verdict to `not_reproduced` and keep the evidence of the attempt.
That is a useful result and stops others repeating the work.

**Why is egress disabled?**
So a proof-of-concept cannot reach beyond the sandbox, and so the result does not
depend on an external service that may change.

**Does `reproduced` mean the finding is exploitable in production?**
No. It means the bug triggered in the recorded environment. Exposure is a
separate claim, recorded under `reachability`.

**Do I have to include a fix?**
The example includes one and the YAML lists it, but the spec does not say whether
it is required. See the open questions above.

**Can I add my own fields?**
The spec does not define an extension mechanism yet. If you add fields, keep them
out of the existing section names and document them, so they do not clash with
future spec changes.
