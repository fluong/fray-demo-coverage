# fray-demo-coverage

Plan-only regression fixtures for [Fray](https://github.com/fluong/fray).
Resources are **deliberately insecure** so known rules stay open or mitigated
as documented below. **Never `terraform apply`.**

## Purpose

Catch silent verdict regressions across Fray releases: CI plans this root with
LocalStack STS (same shape as `fray-demo-aws`), runs Fray Action, then asserts
`expected/findings.json` against the Action SARIF output.

## Expected findings

| Rule | Address | Verdict | Why |
|------|---------|---------|-----|
| FR-034 | `aws_instance.bastion` | open | Public IP + SSH from `0.0.0.0/0` |
| FR-034 | `aws_autoscaling_group.rdp` | open | LT `$Latest` public NI + RDP from `0.0.0.0/0` |
| FR-034 | `aws_eks_node_group.workers` | open | `remote_access` key, no `source_security_group_ids`, public subnet |
| FR-017 | `signal:iam_service:bedrock` | open | `global.` inference profile → combined Bedrock region `global` |
| FR-004 | `aws_iam_role_policy.bedrock_pinned` | mitigated | InvokeModel on one eu-west-1 foundation-model ARN |
| FR-004 | `aws_iam_role_policy.bedrock_global` | mitigated | InvokeModel on one `global.` inference-profile ARN |
| FR-007 | `aws_iam_role_policy.app` | mitigated | `GetSecretValue` on `secret:<name>-*` for the plan secret |
| FR-032 | `aws_iam_role_policy.app` | mitigated | `s3:GetObject` on `arn:aws:s3:::<bucket>/*` for the plan bucket |
| FR-001 | `aws_apigatewayv2_route.public` | open | HTTP API route `authorization_type = NONE` |
| FR-001 | `aws_lambda_function_url.open` | open | Function URL `authorization_type = NONE` |
| FR-001 | `aws_lb.cognito` | mitigated | Cognito-authenticated HTTPS listener on an internet ALB |

## How the assert works

Fray Action exposes (`action.yml` outputs):

- `has-sarif` — whether `${runner.temp}/fray-out/findings.sarif` was written
- `sarif-file` — absolute path to that SARIF file

`scripts/assert-findings.sh` reads those outputs. SARIF contains **open**
findings only (`render.SARIF`); each result’s `partialFingerprints["fray/v1"]`
is `sha256("<rule_id>|<cause Terraform address>")`. For each expected row:

- **open** → fingerprint (or `match: rule` for signal elements) must be present
- **mitigated** → must be **absent** from SARIF (mitigated findings are omitted)

Assert runs on `push` to `main` and `workflow_dispatch` only.

### Gate vs planted highs

Intentionally open **high** findings (FR-034) do not fail the job once they
are on the merge baseline. The Action `Gate` step fails only when the API sets
`gate.blocked` for **new** high findings vs baseline. A default-branch scan
sets that baseline (`is_default_branch`); the first scan uses gate mode
`none`, later ones `diff`. See `fluong/fray` `action.yml` (Gate step) and
`fray-server` `classifyBaseline` / `Gate`.

## Updating `expected/findings.json`

When a Fray release intentionally changes a verdict:

1. Confirm the new verdict against rule docs / release notes.
2. Edit the row in `expected/findings.json` (and the table above).
3. Re-run `workflow_dispatch` (or push to `main`) and confirm assert passes.

Do not waive planted findings to silence the assert — change the expected row
or the fixture.

## Enrollment

Add this repository to the existing Fray GitHub App installation. Scan
admission is automatic via the `installation_repositories` webhook (not the
dashboard B-27 allowlist). Free-plan orgs have a 3-repo cap unless
`design_partner`.

## Local plan (optional)

```bash
cd infra
# Dummy AWS_* as in CI; no apply.
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
terraform init -backend=false
terraform validate
# terraform plan needs LocalStack STS or skip — CI uses the workflow service.
```

Never apply.
