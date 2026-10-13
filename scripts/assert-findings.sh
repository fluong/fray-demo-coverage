#!/usr/bin/env bash
# Compare Fray Action outputs under ${runner.temp}/fray-out to expected/findings.json.
#
# Action outputs (fluong/fray action.yml):
#   has-sarif  — whether findings.sarif was written
#   sarif-file — absolute path to ${runner.temp}/fray-out/findings.sarif
#
# Files the client writes to -out / FRAY_OUT (cmd/fray/remote.go + action/scan.sh):
#   findings.json     — all findings (rule_id, target id, status, severity); no addresses
#   findings.sarif    — open findings only; partialFingerprints["fray/v1"]
#   threat-model.md
#   pr-comment.md
#   payload.json      — when show-payload (exact POST body; redacted DFD)
#   enrollment.json   — on enrollment soft-skip only
#   base-source/      — when scanning a PR with base-commit
#
# Open rows: SARIF fingerprint (or match:"rule") must be present; exact-set —
# every SARIF open must be expected open or known_incidental.
# Mitigated rows: require findings.json status=mitigated for the rule (no
# address on wire), plus optional dfd_evidence checks against payload.json.
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

FRAY_OUT="$(cd "$(dirname "$SARIF_FILE")" && pwd)"
FINDINGS_JSON="${FINDINGS_JSON:-${FRAY_OUT}/findings.json}"
PAYLOAD_JSON="${PAYLOAD_JSON:-${FRAY_OUT}/payload.json}"

python3 - "${EXPECTED}" "${SARIF_FILE}" "${FINDINGS_JSON}" "${PAYLOAD_JSON}" <<'PY'
import hashlib, json, sys
from pathlib import Path

expected_path, sarif_path, findings_path, payload_path = sys.argv[1:5]
exp = json.load(open(expected_path))
sarif = json.load(open(sarif_path))

def fingerprint(rule: str, address: str) -> str:
    return hashlib.sha256(f"{rule}|{address}".encode()).hexdigest()

results = []
for run in sarif.get("runs") or []:
    results.extend(run.get("results") or [])

# Map fingerprint → ruleId for exact-set checks.
sarif_fps: dict[str, str] = {}
rules_present: set[str] = set()
for r in results:
    rule = r.get("ruleId") or ""
    rules_present.add(rule)
    fp = (r.get("partialFingerprints") or {}).get("fray/v1")
    if fp:
        sarif_fps[fp] = rule

errors: list[str] = []

# --- expected open / mitigated rows ---
expected_open_fps: set[str] = set()
expected_open_rules_match: set[str] = set()  # match:"rule" opens
mitigated_by_rule: dict[str, int] = {}

for row in exp.get("findings") or []:
    rule = row["rule"]
    address = row["address"]
    verdict = row["verdict"]
    match = row.get("match", "fingerprint")
    label = f"{rule} @ {address} (want {verdict})"

    if verdict == "open":
        if match == "rule":
            expected_open_rules_match.add(rule)
            if rule not in rules_present:
                errors.append(f"missing open rule in SARIF: {label}")
        else:
            fp = fingerprint(rule, address)
            expected_open_fps.add(fp)
            if fp not in sarif_fps:
                got = sorted(fp_ for fp_, r in sarif_fps.items() if r == rule) or ["(none)"]
                errors.append(
                    f"missing open finding in SARIF: {label}\n"
                    f"  expected fray/v1={fp}\n"
                    f"  got for {rule}: {got}"
                )
    else:
        # Mitigated/unverified must not appear as open fingerprints.
        if match != "rule":
            fp = fingerprint(rule, address)
            if fp in sarif_fps:
                errors.append(f"SARIF has finding that should be {verdict}: {label} fp={fp}")
        mitigated_by_rule[rule] = mitigated_by_rule.get(rule, 0) + 1

# --- known incidental opens (allowed extras) ---
incidental_fps: set[str] = set()
incidental_rules_match: set[str] = set()
for row in exp.get("known_incidental") or []:
    rule = row["rule"]
    address = row["address"]
    match = row.get("match", "fingerprint")
    if match == "rule":
        incidental_rules_match.add(rule)
    else:
        incidental_fps.add(fingerprint(rule, address))

# --- exact open set: every SARIF result must be expected or incidental ---
allowed_fps = expected_open_fps | incidental_fps
allowed_rules = expected_open_rules_match | incidental_rules_match
for fp, rule in sorted(sarif_fps.items(), key=lambda x: (x[1], x[0])):
    if fp in allowed_fps:
        continue
    if rule in allowed_rules:
        # match:"rule" rows allow any fingerprint for that ruleId
        continue
    errors.append(
        f"unexpected open in SARIF: rule={rule} fray/v1={fp} "
        f"(add to findings or known_incidental)"
    )

# --- findings.json: positive status for mitigated rows (no addresses on wire) ---
findings_file = Path(findings_path)
if mitigated_by_rule:
    if not findings_file.is_file():
        errors.append(
            f"mitigated rows require {findings_path} (cmd/fray writes findings.json to -out); missing"
        )
    else:
        doc = json.load(open(findings_file))
        status_counts: dict[tuple[str, str], int] = {}
        for f in doc.get("findings") or []:
            key = (f.get("rule_id") or "", f.get("status") or "")
            status_counts[key] = status_counts.get(key, 0) + 1
        for rule, want_n in sorted(mitigated_by_rule.items()):
            got = status_counts.get((rule, "mitigated"), 0)
            if got < want_n:
                errors.append(
                    f"findings.json: want ≥{want_n} mitigated {rule}, got {got} "
                    f"(target ids only — no Terraform address on wire)"
                )

# --- payload.json DFD attribute evidence for mitigated drivers ---
payload_file = Path(payload_path)
dfd_checks = exp.get("dfd_evidence") or []
if dfd_checks:
    if not payload_file.is_file():
        errors.append(
            f"dfd_evidence requires {payload_path} (enable show-payload); missing"
        )
    else:
        body = json.load(open(payload_file))
        dfd = body.get("dfd")
        if isinstance(dfd, str):
            dfd = json.loads(dfd)
        if not isinstance(dfd, dict):
            errors.append("payload.json: dfd missing or not an object")
        else:
            elements = {el.get("id"): el for el in (dfd.get("elements") or []) if el.get("id")}
            # Also index by kind for authz checks (ids may be redacted/HMAC).
            flows = dfd.get("flows") or []

            def el_kind(eid: str) -> str:
                el = elements.get(eid) or {}
                return el.get("kind") or ""

            for check in dfd_checks:
                cid = check.get("id") or check.get("for") or "check"
                req = check.get("require") or {}
                ok = False
                if "flow" in req:
                    want = req["flow"]
                    for fl in flows:
                        if want.get("authz_scope") and fl.get("authz_scope") != want["authz_scope"]:
                            continue
                        if want.get("to_kind") and el_kind(fl.get("to") or "") != want["to_kind"]:
                            continue
                        if want.get("from_kind") and el_kind(fl.get("from") or "") != want["from_kind"]:
                            continue
                        ok = True
                        break
                elif "element" in req:
                    want = req["element"]
                    for el in elements.values():
                        if want.get("kind") and el.get("kind") != want["kind"]:
                            continue
                        attrs = el.get("attributes") or {}
                        attr_ok = True
                        for k, v in (want.get("attributes") or {}).items():
                            if attrs.get(k) != v:
                                attr_ok = False
                                break
                        if attr_ok and want.get("attributes"):
                            ok = True
                            break
                        if not want.get("attributes") and want.get("kind"):
                            ok = True
                            break
                else:
                    errors.append(f"dfd_evidence {cid}: need require.flow or require.element")
                    continue
                if not ok:
                    errors.append(f"dfd_evidence failed: {cid} require={req}")

if errors:
    print("assert-findings failed:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)

n_findings = len(exp.get("findings") or [])
n_inc = len(exp.get("known_incidental") or [])
print(
    f"assert-findings: {n_findings} expected + {n_inc} incidental OK; "
    f"SARIF opens={len(sarif_fps)} against {sarif_path}"
)
PY
