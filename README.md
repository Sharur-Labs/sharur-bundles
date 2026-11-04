# Sharur Bundle Spec

A specification for **Sharur bundles**: a portable, self-contained record that a
reported security finding is real, reproducible, and (optionally) fixed.

Automated security tools produce a lot of findings, and many of them are false
positives. A Sharur bundle replaces "trust me, there's a bug" with the evidence a
reviewer needs to check it: the exact code and build, the isolated environment,
the exploit, the oracle that confirmed the effect, a deterministic replay, an
exposure assessment, a candidate fix, and an audit trail of what was done.

## Where Sharur bundles come from

Sharur bundles are the output format of an **agentic vulnerability-reproduction
engine**: a system in which AI agents take a reported finding, try to reproduce
it in an isolated environment, and record the result. That engine is under
development and is **not open source**. It does not live in this repo.

This repo holds only the **public contract**: the spec and a worked example that
describe what such an engine emits and what a reviewer or downstream tool can
rely on. It contains no engine code, no agent prompts and no tooling to generate
bundles. The format is described independently of the engine so that anyone can
read, check and consume a bundle without access to the engine that made it.

> **Status: draft.** The spec is early and carries no version number yet. See
> [Changes from earlier drafts and open questions](DOCS.md#8-changes-from-earlier-drafts-and-open-questions)
> in `DOCS.md`.

## What's in this repo

| File | Purpose |
| --- | --- |
| [`sharur-bundle-spec.yaml`](sharur-bundle-spec.yaml) | **The spec.** Every section and field with its type, plus the allowed `severity` and `verdict` values. It contains types, not values. |
| [`sharur-bundle.json`](sharur-bundle.json) | **An example** of a bundle written as JSON. Its `...` placeholders stand for "a string goes here". If it disagrees with the YAML, the YAML wins. |
| [`DOCS.md`](DOCS.md) | The usage guide: a field-by-field reference, how to produce a bundle, how to review one, and the known gaps. |
| `README.md` | This file. |

## What a Sharur bundle contains

A bundle is one JSON document with these sections. Each answers one question a
reviewer would ask.

| Section | Question it answers |
| --- | --- |
| `finding_id`, `source` | Which finding is this, and which tool reported it? |
| `target` (+ `build`) | Exactly which code, at which commit, built how? |
| `environment` | Where did the exploit run? Was it isolated? |
| `exploit` | What was run to trigger the bug? |
| `oracle` | What objective signal confirmed it (for example an ASan report)? |
| `replay` | Can someone else reproduce it deterministically? |
| `reachability` | Can an attacker actually reach it, and how severe is it? |
| `dedup` | Is this the same root cause as another finding? |
| `fix` | Is there a patch, does it stop the exploit, and do tests still pass? |
| `audit` | Who authorised the work, and what actions were taken? |
| `verdict` | Was the finding reproduced? |

## Quick start

Look at the example, then check that a bundle has every top-level section:

```bash
jq . sharur-bundle.json

jq -e 'def req: ["finding_id","source","target","environment","exploit","oracle",
                 "replay","reachability","dedup","fix","audit","verdict"];
       (req - keys) as $m
       | if ($m|length)==0 then "ok" else error("missing: \($m|join(","))") end' \
   sharur-bundle.json
```

For a full walkthrough, including how to produce and review a bundle and what
each field means, read [`DOCS.md`](DOCS.md).

## Design principles

- **Evidence over assertion.** A `verdict` is only as good as the oracle, replay
  and environment sections behind it.
- **Reproducible.** The target is pinned to a commit and a build recipe or image
  digest, and the replay is seeded.
- **Safe by default.** Exploits run in a microVM with network egress disabled.
- **Accountable.** A signed scope and an action log record who authorised the
  testing and what was done.
- **Deduplicated.** A root-cause hash lets many reports collapse into one
  cluster.

## Contributing

Contributions here are to the spec, the example and the docs, not to the engine,
which is developed separately. The spec is still taking shape, so the most useful
contributions right now are:

- settling the [open questions](DOCS.md#8-changes-from-earlier-drafts-and-open-questions)
  (required vs optional fields, an egress enum, a version field);
- generating a machine-checkable schema (for example JSON Schema) from
  `sharur-bundle-spec.yaml`;
- adding real, anonymised example bundles.

Open an issue or pull request describing the change. Edit the YAML first, then
update the example bundle and `DOCS.md` in the same change so the three stay in
sync.
