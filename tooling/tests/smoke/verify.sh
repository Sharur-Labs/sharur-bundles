#!/usr/bin/env bash
# Verifier smoke test: drive the installed `sharur-verify` CLI the way a third
# party would, and check exit codes and reported issues.
#
#   1. the sample bundle conforms, even with --strict                      -> 0
#   2. the repo's example document conforms in shape but has placeholders,
#      so it passes normally and fails --strict                            -> 0 / 1
#   3. every conformance fixture reports exactly the errors and warnings
#      listed in conformance/expected.json, with the right exit code
#   4. a bundle missing a companion file fails                             -> 1
#   5. a path with no bundle in it is an I/O error                         -> 2
#
# Requires jq.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
conformance="$here/conformance"
cli="${SHARUR_VERIFY:-sharur-verify}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

expect() {
  local want="$1" name="$2"; shift 2
  set +e
  "$@" >"$work/out" 2>&1
  local got=$?
  set -e
  if [[ "$got" -ne "$want" ]]; then
    echo "FAIL: $name (exit $got, expected $want)"
    cat "$work/out"
    failures=$((failures + 1))
    return 0
  fi
  echo "ok:   $name (exit $got)"
}

expect 0 "sample bundle conforms (strict)" "$cli" --strict "$here/pcf-2026-0001"
expect 0 "repo example conforms in shape" "$cli" --skip-files "$repo/sharur-bundle.json"
expect 1 "repo example fails strict (placeholders)" "$cli" --skip-files --strict "$repo/sharur-bundle.json"

# Conformance fixtures: compare the (code, path) pairs the CLI reports with
# the expected set, and check the exit code with and without --strict.
while IFS= read -r case; do
  want_errors="$(jq -c --arg c "$case" '.[$c].errors' "$conformance/expected.json")"
  want_warnings="$(jq -c --arg c "$case" '.[$c].warnings' "$conformance/expected.json")"

  set +e
  "$cli" --skip-files --format json "$conformance/$case" >"$work/report.json"
  rc=$?
  "$cli" --skip-files --strict "$conformance/$case" >/dev/null
  strict_rc=$?
  set -e

  got_errors="$(jq -c '[(.[0].errors // [])[] | [.code, .path]] | sort' "$work/report.json" 2>/dev/null || echo invalid-report)"
  got_warnings="$(jq -c '[(.[0].warnings // [])[] | [.code, .path]] | sort' "$work/report.json" 2>/dev/null || echo invalid-report)"
  case "$case" in
    invalid/*) want_rc=1 ;;
    *) want_rc=0 ;;
  esac

  if [[ "$got_errors" == "$want_errors" && "$got_warnings" == "$want_warnings" \
        && "$rc" -eq "$want_rc" && "$strict_rc" -eq 1 ]]; then
    echo "ok:   conformance $case"
  else
    echo "FAIL: conformance $case"
    echo "      exit $rc (want $want_rc), strict exit $strict_rc (want 1)"
    echo "      errors   got $got_errors want $want_errors"
    echo "      warnings got $got_warnings want $want_warnings"
    failures=$((failures + 1))
  fi
done < <(jq -r 'keys[]' "$conformance/expected.json")

cp -r "$here/pcf-2026-0001" "$work/incomplete"
rm "$work/incomplete/trace.jsonl"
expect 1 "bundle missing a companion file fails" "$cli" "$work/incomplete"
grep -q "error\[file-missing\] replay.trace" "$work/out" || { echo "FAIL: file-missing not reported"; failures=$((failures + 1)); }

expect 2 "path without a bundle is an I/O error" "$cli" "$work/does-not-exist"

if [[ "$failures" -ne 0 ]]; then
  echo "$failures verifier smoke check(s) failed"
  exit 1
fi
echo "verifier smoke tests passed"
