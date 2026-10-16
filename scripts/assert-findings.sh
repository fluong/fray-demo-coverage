#!/usr/bin/env bash
# Compare Fray Action outputs under ${runner.temp}/fray-out to expected/findings.json.
#
# Action outputs (fluong/fray action.yml):
#   has-sarif  — whether findings.sarif was written
#   sarif-file — absolute path to ${runner.temp}/fray-out/findings.sarif
#
# Files the client writes to -out / FRAY_OUT (cmd/fray/remote.go + action/scan.sh):
#   findings.json     — all findings (rule_id, target, status, severity) plus
#                       optional local `addresses` (Terraform addresses; fray ≥ v0.26.0)
#   findings.sarif    — open findings only; partialFingerprints["fray/v1"]
#                       = sha256("<rule_id>|<cause address>") (render.Fingerprint)
#   threat-model.md
#   pr-comment.md
#   payload.json      — when show-payload (exact POST body; redacted DFD)
#   enrollment.json   — on enrollment soft-skip only
#   base-source/      — when scanning a PR with base-commit
#
# Open rows: SARIF fingerprint (flow.cause, element address, or match:"rule")
# must be present; exact-set — every SARIF open must be expected open or
# known_incidental.
# Mitigated / unverified / waived: findings.json status counts plus
# addresses CONTAINS the expected Terraform address (v0.26.0+).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED="${EXPECTED:-${ROOT}/expected/findings.json}"
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
import hashlib, hmac, json, os, sys
from pathlib import Path

expected_path, sarif_path, findings_path, payload_path = sys.argv[1:5]
exp = json.load(open(expected_path))
sarif = json.load(open(sarif_path))

def fingerprint(rule: str, cause: str) -> str:
    # render.Fingerprint: sha256 hex of "<rule_id>|<cause Terraform address>".
    return hashlib.sha256(f"{rule}|{cause}".encode()).hexdigest()

def flow_cause(flow: dict) -> str:
    """Right-hand side of the client fingerprint for one flow finding.

    CauseAddress (render/comment.go) uses the flow's Causes[failed attribute]
    when that is set, otherwise the To-element address, then the From-element
    address. Causes is not in the DFD JSON. `cause` is that address when it
    is not the To-element (FR-028: the IAM document). Omitted `cause` falls
    back to `to`, then `from` (defaultCause).
    """
    cause = str(flow.get("cause") or "").strip()
    if cause:
        return cause
    to = str(flow.get("to") or "").strip()
    if to:
        return to
    return str(flow.get("from") or "").strip()

def row_open_cause(row: dict) -> str:
    flow = row.get("flow")
    if isinstance(flow, dict):
        return flow_cause(flow)
    return str(row.get("address") or "")

def _redaction_key():
    raw = (os.environ.get("FRAY_REDACTION_KEY") or "").strip()
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None

def hash_address(plaintext):
    key = _redaction_key()
    if key is None:
        return None
    # client.HashField: HMAC-SHA256(key, "address" || 0x00 || value)
    mac = hmac.new(key, b"address\x00" + plaintext.encode(), hashlib.sha256)
    return mac.hexdigest()

def el_addresses(el: dict) -> list[str]:
    return list((el.get("evidence") or {}).get("addresses") or [])

def address_matches(el: dict, want: str) -> bool:
    addrs = el_addresses(el)
    if want in addrs:
        return True
    hashed = hash_address(want)
    return bool(hashed and hashed in addrs)

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

# --- expected open / mitigated / unverified / waived rows ---
expected_open_fps: set[str] = set()
expected_open_rules_match: set[str] = set()  # match:"rule" opens
# (rule, status) → count; status is mitigated, unverified, or waived
status_want: dict[tuple[str, str], int] = {}
# Non-open rows that must match by Terraform address in findings.json.
address_want: list[tuple[str, str, str]] = []  # (rule, status, address)

for row in exp.get("findings") or []:
    rule = row["rule"]
    address = row["address"]
    verdict = row["verdict"]
    match = row.get("match", "fingerprint")
    label = f"{rule} @ {address} (want {verdict})"

    if verdict == "open":
        if match == "rule" and not isinstance(row.get("flow"), dict):
            expected_open_rules_match.add(rule)
            if rule not in rules_present:
                errors.append(f"missing open rule in SARIF: {label}")
        else:
            cause = row_open_cause(row)
            if not cause:
                errors.append(f"open row has no fingerprint cause: {label}")
                continue
            fp = fingerprint(rule, cause)
            expected_open_fps.add(fp)
            if fp not in sarif_fps:
                got = sorted(fp_ for fp_, r in sarif_fps.items() if r == rule) or ["(none)"]
                errors.append(
                    f"missing open finding in SARIF: {label}\n"
                    f"  expected fray/v1={fp}\n"
                    f"  got for {rule}: {got}"
                )
    elif verdict in ("mitigated", "unverified", "waived"):
        # Must not appear as open fingerprints.
        if match != "rule" or isinstance(row.get("flow"), dict):
            cause = row_open_cause(row)
            fp = fingerprint(rule, cause) if cause else ""
            if fp in sarif_fps:
                errors.append(f"SARIF has finding that should be {verdict}: {label} fp={fp}")
        key = (rule, verdict)
        status_want[key] = status_want.get(key, 0) + 1
        address_want.append((rule, verdict, address))
    else:
        errors.append(f"unknown verdict {verdict!r} for {label}")

# --- known incidental opens (allowed extras) ---
incidental_fps: set[str] = set()
incidental_rules_match: set[str] = set()
for row in exp.get("known_incidental") or []:
    rule = row["rule"]
    address = row["address"]
    match = row.get("match", "fingerprint")
    if match == "rule" and not isinstance(row.get("flow"), dict):
        incidental_rules_match.add(rule)
    else:
        cause = row_open_cause(row)
        if cause:
            incidental_fps.add(fingerprint(rule, cause))

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

# --- findings.json: status counts + address membership (fray ≥ v0.26.0) ---
findings_file = Path(findings_path)
if status_want or address_want:
    if not findings_file.is_file():
        errors.append(
            f"mitigated/unverified/waived rows require {findings_path} "
            f"(cmd/fray writes findings.json to -out); missing"
        )
    else:
        doc = json.load(open(findings_file))
        raw_findings = doc.get("findings") or []
        status_counts: dict[tuple[str, str], int] = {}
        # (rule, status) → list of address lists seen (for error reporting)
        addrs_by_key: dict[tuple[str, str], list[list[str]]] = {}
        any_addresses_field = False
        for f in raw_findings:
            key = (f.get("rule_id") or "", f.get("status") or "")
            status_counts[key] = status_counts.get(key, 0) + 1
            if "addresses" in f:
                any_addresses_field = True
                addrs_by_key.setdefault(key, []).append(list(f.get("addresses") or []))
            else:
                addrs_by_key.setdefault(key, []).append([])

        for (rule, status), want_n in sorted(status_want.items()):
            got = status_counts.get((rule, status), 0)
            if got < want_n:
                errors.append(
                    f"findings.json: want ≥{want_n} {status} {rule}, got {got}"
                )

        if address_want and not any_addresses_field:
            errors.append(
                f"{findings_path}: no finding has an `addresses` field — "
                f"pinned fray is older than v0.26.0 (need local Terraform addresses)"
            )
        else:
            for rule, status, address in address_want:
                key = (rule, status)
                seen_lists = addrs_by_key.get(key) or []
                matched = any(address in addrs for addrs in seen_lists)
                if not matched:
                    flat = sorted({a for addrs in seen_lists for a in addrs}) or ["(none)"]
                    errors.append(
                        f"expected {rule} {status} at {address}: not found "
                        f"(addresses seen for {rule}/{status}: {flat})"
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

            def el_by_id(eid: str) -> dict:
                return elements.get(eid) or {}

            def flow_matches(fl: dict, want: dict) -> bool:
                if want.get("authz_scope_absent"):
                    if fl.get("authz_scope") is not None:
                        return False
                elif want.get("authz_scope") and fl.get("authz_scope") != want["authz_scope"]:
                    return False
                if want.get("secret_delivery") and fl.get("secret_delivery") != want["secret_delivery"]:
                    return False
                if want.get("data_class") and fl.get("data_class") != want["data_class"]:
                    return False
                if want.get("to_kind") and el_kind(fl.get("to") or "") != want["to_kind"]:
                    return False
                if want.get("from_kind") and el_kind(fl.get("from") or "") != want["from_kind"]:
                    return False
                if want.get("from_address"):
                    if not address_matches(el_by_id(fl.get("from") or ""), want["from_address"]):
                        return False
                if want.get("to_address"):
                    if not address_matches(el_by_id(fl.get("to") or ""), want["to_address"]):
                        return False
                return True

            for check in dfd_checks:
                cid = check.get("id") or check.get("for") or "check"
                req = check.get("require") or {}
                ok = False
                if "flow" in req:
                    want = req["flow"]
                    hits = [fl for fl in flows if flow_matches(fl, want)]
                    if want.get("absent"):
                        ok = len(hits) == 0
                    else:
                        min_count = want.get("min_count")
                        exact_count = want.get("exact_count")
                        if exact_count is not None:
                            ok = len(hits) == exact_count
                        elif min_count is not None:
                            ok = len(hits) >= min_count
                        else:
                            ok = len(hits) >= 1
                        if ok and want.get("unique_from"):
                            froms = [fl.get("from") for fl in hits]
                            ok = len(froms) == len(set(froms))
                        if ok and want.get("unique_to"):
                            tos = [fl.get("to") for fl in hits]
                            ok = len(tos) == len(set(tos))
                elif "element" in req:
                    want = req["element"]
                    for el in elements.values():
                        if want.get("kind") and el.get("kind") != want["kind"]:
                            continue
                        if want.get("address") and not address_matches(el, want["address"]):
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
                        if not want.get("attributes") and (want.get("kind") or want.get("address")):
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
