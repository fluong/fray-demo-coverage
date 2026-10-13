#!/usr/bin/env bash
# Compare Fray Action SARIF output to expected/findings.json.
#
# Action outputs (fluong/fray action.yml):
#   has-sarif  — whether findings.sarif was written
#   sarif-file — absolute path to ${runner.temp}/fray-out/findings.sarif
#
# SARIF (render.SARIF): open findings only; mitigated/waived omitted.
# partialFingerprints["fray/v1"] = sha256 hex of "<rule_id>|<cause address>"
# (or "<rule_id>|<DFD id>" when cause is empty — see match:"rule" rows).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED="${ROOT}/expected/findings.json"
SARIF_FILE="${SARIF_FILE:-${1:-}}"
HAS_SARIF="${HAS_SARIF:-true}"

if [[ "${HAS_SARIF}" != "true" ]]; then
  echo "::error::Fray did not write findings.sarif (has-sarif=${HAS_SARIF}). Enrollment soft-skip?"
  exit 1
fi
if [[ -z "${SARIF_FILE}" || ! -f "${SARIF_FILE}" ]]; then
  echo "::error::SARIF_FILE missing or not a file: '${SARIF_FILE}'"
  exit 1
fi
if [[ ! -f "${EXPECTED}" ]]; then
  echo "::error::missing ${EXPECTED}"
  exit 1
fi

python3 - "${EXPECTED}" "${SARIF_FILE}" <<'PY'
import hashlib, json, sys

expected_path, sarif_path = sys.argv[1], sys.argv[2]
exp = json.load(open(expected_path))
sarif = json.load(open(sarif_path))

def fingerprint(rule: str, address: str) -> str:
    return hashlib.sha256(f"{rule}|{address}".encode()).hexdigest()

results = []
for run in sarif.get("runs") or []:
    results.extend(run.get("results") or [])

fps_by_rule: dict[str, set[str]] = {}
rules_present: set[str] = set()
for r in results:
    rule = r.get("ruleId") or ""
    rules_present.add(rule)
    fp = (r.get("partialFingerprints") or {}).get("fray/v1")
    if fp:
        fps_by_rule.setdefault(rule, set()).add(fp)

errors = []
for row in exp.get("findings") or []:
    rule = row["rule"]
    address = row["address"]
    verdict = row["verdict"]
    match = row.get("match", "fingerprint")
    label = f"{rule} @ {address} (want {verdict})"

    if match == "rule":
        present = rule in rules_present
        if verdict == "open" and not present:
            errors.append(f"missing open rule in SARIF: {label}")
        elif verdict != "open" and present:
            errors.append(f"SARIF still has rule (expected {verdict}): {label}")
        continue

    fp = fingerprint(rule, address)
    present = fp in fps_by_rule.get(rule, set())
    if verdict == "open":
        if not present:
            errors.append(
                f"missing open finding in SARIF: {label}\n"
                f"  expected fray/v1={fp}\n"
                f"  got for {rule}: {sorted(fps_by_rule.get(rule, [])) or '(none)'}"
            )
    else:
        # mitigated / unverified / waived are omitted from SARIF
        if present:
            errors.append(f"SARIF has finding that should be {verdict}: {label} fp={fp}")

if errors:
    print("assert-findings failed:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)

print(f"assert-findings: {len(exp.get('findings') or [])} expected rows OK against {sarif_path}")
PY
