#!/usr/bin/env bash
# Replayer smoke test: drive the installed `sharur-replay` CLI against the
# hand-made sample bundle and check each exit code.
#
#   1. the sample conforms to the spec (sharur-verify --strict)
#   2. the signed sample replays and matches its recorded verdict      -> 0
#   3. a tampered copy is rejected by signature verification           -> 2
#   4. with fix.diff applied the oracle goes quiet, so the recorded
#      "reproduced" verdict no longer matches                          -> 1
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle="$here/pcf-2026-0001"
pubkey="$here/keys/sample-signer.pub.pem"
cli="${SHARUR_REPLAY:-sharur-replay}"
verifier="${SHARUR_VERIFY:-sharur-verify}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

expect() {
  local want="$1" name="$2"; shift 2
  set +e
  "$@" >"$work/out" 2>&1
  local got=$?
  set -e
  if [[ "$got" -ne "$want" ]]; then
    echo "FAIL: $name (exit $got, expected $want)"
    cat "$work/out"
    exit 1
  fi
  echo "ok:   $name (exit $got)"
}

expect 0 "sample conforms to the spec" "$verifier" --strict "$bundle"

expect 0 "signed sample replays to recorded verdict" \
  "$cli" replay "$bundle" --unsafe-local --pubkey "$pubkey"
cat "$work/out"

cp -r "$bundle" "$work/tampered"
printf '\n# tampered\n' >>"$work/tampered/poc.py"
expect 2 "tampered sample is rejected" \
  "$cli" replay "$work/tampered" --unsafe-local --pubkey "$pubkey"

cp -r "$bundle" "$work/fixed"
(cd "$work/fixed" && git apply fix.diff)
expect 1 "patched sample no longer reproduces" \
  "$cli" replay "$work/fixed" --unsafe-local --runs 1

echo "replayer smoke tests passed"
