# fray-demo-coverage

Plan-only regression fixtures for [Fray](https://github.com/fluong/fray).
Resources are **deliberately insecure** so known rules stay open or mitigated
as documented below. **Never `terraform apply`.**

## Purpose

Catch silent verdict regressions across Fray releases: CI plans this root with
LocalStack STS (same shape as `fray-demo-aws`), runs Fray Action, then asserts
`expected/findings.json` against the Action outputs under
`${runner.temp}/fray-out`.

## Leak guards

Same fail-closed checks as public `fluong/fray` (gitleaks + internal-identifier
denylist). `fray-demo-aws` does not ship these yet; this repo mirrors `fray`.

```bash
./scripts/install-hooks.sh   # once per clone; sets core.hooksPath=.githooks
```

Pre-push refuses the push on a gitleaks or denylist hit. Requires `gitleaks` on
`PATH` (`brew install gitleaks`). Patterns come from the `FRAY_DENYLIST`
repository secret (CI) or `FRAY_DENYLIST` / `~/.config/fray/denylist` locally —
**never committed** (patterns name private identifiers). Missing list fails
closed.

CI runs the same pair in the `guards` job in `.github/workflows/fray.yml`.
Fork PRs cannot read the denylist secret; a maintainer re-runs from a trusted
context.

## Expected findings

| Rule | Address | Verdict | Why |
|------|---------|---------|-----|
| FR-034 | `aws_instance.bastion` | open | Public IP + SSH from `0.0.0.0/0` |
| FR-034 | `aws_autoscaling_group.rdp` | open | LT `$Latest` public NI + RDP from `0.0.0.0/0` |
| FR-034 | `aws_eks_node_group.workers` | open | `remote_access` key, no `source_security_group_ids`, public subnet |
| FR-017 | `signal:iam_service:bedrock` | open | `global.` inference profile → combined Bedrock region `global` |
| FR-004 | `aws_lambda_function.bedrock_pinned` | mitigated | InvokeModel on one eu-west-1 foundation-model ARN |
| FR-004 | `aws_lambda_function.bedrock_global` | mitigated | InvokeModel on one `global.` inference-profile ARN |
| FR-032 | `aws_s3_bucket.uploads` | mitigated | Literal + plan-time data-doc ARNs on app task role → uploads |
| FR-032 | `aws_s3_bucket.worker` | mitigated | Same IAM shapes on worker task role → worker bucket (B-44) |
| FR-007 | `aws_ecs_service.app` | mitigated | Execution role GetSecretValue scoped to app secret (B-43) |
| FR-001 | `aws_apigatewayv2_route.public` | open | HTTP API route `authorization_type = NONE` |
| FR-001 | `aws_lambda_function_url.open` | open | Function URL `authorization_type = NONE` |
| FR-001 | `aws_lb.cognito` | mitigated | Cognito-authenticated HTTPS listener on an internet ALB |

Flat layout (four files, no modules). Two root ECS task definitions (`app`,
`worker`) each with their own task role and bucket. App task def references a
root secret via `valueFrom = aws_secretsmanager_secret.app.arn` (same-plan
create → `container_definitions` unknown; Fray reads it from the configuration).

Pinned Fray Action: **v0.26.1**.

### Known gaps

None currently.

### Known incidental opens

Fixture noise that must stay open in SARIF but is not a coverage target.
Listed under `known_incidental` in `expected/findings.json` (exact-set assert).

| Rule | Address | Why |
|------|---------|-----|
| FR-005 | `aws_ecs_service.app` | Mutable `nginx:1.27` tag |
| FR-005 | `aws_ecs_service.worker` | Mutable `nginx:1.27` tag |
| FR-003 | `aws_ecs_service.app` | ECS `secrets[].valueFrom` is always env injection |
| FR-009 | `aws_secretsmanager_secret.app` | No rotation on the coverage secret |

## How the assert works

Fray Action exposes (`action.yml` outputs):

- `has-sarif` — whether `findings.sarif` was written
- `sarif-file` — absolute path to `${runner.temp}/fray-out/findings.sarif`

Sibling files in the same `FRAY_OUT` directory (`cmd/fray/remote.go`,
`action/scan.sh`):

| File | Contents |
|------|----------|
| `findings.json` | All findings: `rule_id`, `target` (DFD id), `status`, `severity`, optional local `addresses` (fray v0.26.1+) |
| `findings.sarif` | **Open** findings only; `partialFingerprints["fray/v1"]` = `sha256(rule\|cause)` |
| `threat-model.md` | Human report |
| `pr-comment.md` | PR comment body |
| `payload.json` | Exact POST body when `show-payload: true` (redacted DFD) |
| `enrollment.json` | Enrollment soft-skip marker only |
| `base-source/` | Base-commit tree when comparing a PR |

`scripts/assert-findings.sh`:

1. **Open (coverage):** SARIF fingerprint (or `match: rule`) present.
2. **Exact open set:** every SARIF open is an expected open or `known_incidental`.
3. **Mitigated / unverified / waived:** status counts in `findings.json`, and each expected address must appear in a matching finding’s `addresses` list.
4. **DFD evidence:** `payload.json` flows/elements carry the attributes that drive mitigated/open drivers (`authz_scope`, `region`, kinds).

Mitigated, unverified and waived results are checked by Terraform address (`findings.json` `addresses`, fray v0.26.1+).

Assert runs on `push` to `main` and `workflow_dispatch` only.

### Gate vs planted highs

Intentionally open **high** findings (FR-034) do not fail the job once they
are on the merge baseline. The Action `Gate` step fails only when the API sets
`gate.blocked` for **new** high findings vs baseline. A default-branch scan
sets that baseline (`is_default_branch`); the first scan uses gate mode
`none`, later ones `diff`. See `fluong/fray` `action.yml` (Gate step).

## Updating `expected/findings.json`

When a Fray release intentionally changes a verdict:

1. Confirm the new verdict against rule docs / release notes.
2. Edit the row (and tables above). New unexpected opens → `known_incidental`
   with a reason, or fix the fixture.
3. Re-run `workflow_dispatch` (or push to `main`) and confirm assert passes.

## Enrollment

Add this repository to the existing Fray GitHub App installation. Scan
admission is automatic via the `installation_repositories` webhook (not the
dashboard B-27 allowlist). Free-plan orgs have a **3 active
`installation_repos` per org** cap unless `design_partner`.

## Local plan (optional)

```bash
cd infra
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
terraform init -backend=false
terraform validate
```

Never apply.

## Contributing

The provider lock file is generated in CI (Actions → lock → Run workflow), never locally.
To update providers: bump terraform.tf, run the lock workflow, commit its artifact.
