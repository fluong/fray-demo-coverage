#!/usr/bin/env bash
# Local checks for flow fingerprints in assert-findings.sh.
# Fingerprint formula matches fluong/fray render.Fingerprint:
# sha256("<rule_id>|<cause address>").
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSERT="${ROOT}/scripts/assert-findings.sh"
WANT_FR028="d6a59b885bbc5bb3dce03449e0d190c6db1863fd9f28b321ebcbdc9e26a27eff"

python3 - <<PY
import hashlib
got = hashlib.sha256(b"FR-028|data.aws_iam_policy_document.worker_rds").hexdigest()
want = "${WANT_FR028}"
if got != want:
    raise SystemExit(f"FR-028 cause hash {got} != {want}")
print(f"fingerprint FR-028|data.aws_iam_policy_document.worker_rds = {got}")
PY

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 - "$tmp" "$WANT_FR028" <<'PY'
import hashlib, json, sys
from pathlib import Path
tmp, want = Path(sys.argv[1]), sys.argv[2]

def fp(rule, cause):
    return hashlib.sha256(f"{rule}|{cause}".encode()).hexdigest()

fr028 = fp("FR-028", "data.aws_iam_policy_document.worker_rds")
if fr028 != want:
    raise SystemExit("fixture hash drifted")
fr036 = fp("FR-036", "aws_s3_bucket.uploads")
fr017 = "a" * 64  # match: rule — any fingerprint for that rule id

sarif = {
    "runs": [{
        "results": [
            {"ruleId": "FR-028", "partialFingerprints": {"fray/v1": fr028}},
            {"ruleId": "FR-036", "partialFingerprints": {"fray/v1": fr036}},
            {"ruleId": "FR-017", "partialFingerprints": {"fray/v1": fr017}},
        ]
    }]
}
expected = {
    "findings": [
        {
            "rule": "FR-028",
            "address": "aws_db_instance.main",
            "verdict": "open",
            "flow": {
                "from": "aws_ecs_service.worker",
                "to": "aws_db_instance.main",
                "data_class": "unknown",
                "cause": "data.aws_iam_policy_document.worker_rds",
            },
        },
        {"rule": "FR-036", "address": "aws_s3_bucket.uploads", "verdict": "open"},
        {
            "rule": "FR-017",
            "address": "signal:iam_service:bedrock",
            "verdict": "open",
            "match": "rule",
        },
        {
            "rule": "FR-031",
            "address": "aws_db_instance.main",
            "verdict": "mitigated",
        },
    ]
}
findings = {
    "findings": [
        {"rule_id": "FR-031", "status": "mitigated", "addresses": ["aws_db_instance.main"]},
    ]
}
(tmp / "findings.sarif").write_text(json.dumps(sarif))
(tmp / "expected.json").write_text(json.dumps(expected))
(tmp / "findings.json").write_text(json.dumps(findings))
print(f"wrote fixture under {tmp}")
PY

EXPECTED="$tmp/expected.json" \
  FINDINGS_JSON="$tmp/findings.json" \
  PAYLOAD_JSON="$tmp/payload-missing.json" \
  bash "$ASSERT" "$tmp/findings.sarif"

# Wrong cause must fail (flow form is exact, not match: rule).
python3 - "$tmp" <<'PY'
import json, sys
from pathlib import Path
tmp = Path(sys.argv[1])
exp = json.loads((tmp / "expected.json").read_text())
exp["findings"][0]["flow"]["cause"] = "aws_iam_role_policy.worker_rds"
(tmp / "expected-bad.json").write_text(json.dumps(exp))
PY

set +e
EXPECTED="$tmp/expected-bad.json" \
  FINDINGS_JSON="$tmp/findings.json" \
  PAYLOAD_JSON="$tmp/payload-missing.json" \
  bash "$ASSERT" "$tmp/findings.sarif" >"$tmp/bad.out" 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  echo "expected assert to fail on wrong flow cause" >&2
  exit 1
fi
if ! grep -q "missing open finding in SARIF" "$tmp/bad.out"; then
  echo "wrong-cause failure did not name the missing fingerprint:" >&2
  cat "$tmp/bad.out" >&2
  exit 1
fi
echo "assert-findings_test: flow cause hash, element address, match:rule, and wrong-cause rejection OK"
