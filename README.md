# fray-demo-coverage

Plan-only regression fixtures for [Fray](https://github.com/fluong/fray).
Resources are **deliberately insecure** so known rules stay open or mitigated
as documented below. **Never `terraform apply`.**

## Purpose

Catch silent verdict regressions across Fray releases: CI plans this root with
LocalStack STS (same shape as `fray-demo-aws`), runs Fray Action, then asserts
`expected/findings.json` against the Action outputs under
`${runner.temp}/fray-out`.

A second job scans the same stack under `stack: alt` to check that stacks are
kept apart (separate baseline, comment marker and Code Scanning category).

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

Flat layout (four files, no modules). Root ECS task definitions `app` and
`worker` each have their own task role and bucket. `aws_ecs_service.declared`
reaches the same database through its security group. Its task role attaches the
database grant only as a managed-policy ARN (no in-plan policy document):

- `fray.yaml` `annotations.flows` fills `authz_scope: account` for
  `aws_ecs_service.declared` → `aws_db_instance.main` (requires Action v0.32.0 or
  later; older Actions reject the field).
- That gives the open FR-028 row with cause
  `fray.yaml#aws_ecs_service.declared -> aws_db_instance.main unknown`, plus the
  `declared-db-scope-account` `dfd_evidence`.
- The FR-005 row on the service stays `known_incidental`.
The app task def references a root secret via
`valueFrom = aws_secretsmanager_secret.app.arn` (same-plan create →
`container_definitions` unknown; Fray reads it from the configuration).

Pinned Fray Action: **v0.32.0** (see `.github/workflows/fray.yml`).

### B-14 instance-profile workloads (infra now)

Two extra compute paths exercise IAM instance profiles (plan-only, private
subnets, no world-open admin ports):

| Resource | IAM | Intended coverage (client) |
|----------|-----|----------------------------|
| `aws_instance.app_vm` | `ec2_app` → S3 Put/Get on `uploads` only | FR-032 mitigated on `app_vm`→`uploads` once IAM-derived VM flows ship |
| `aws_autoscaling_group.db_worker` | `asg_db` → `rds-db:connect` on `*` via pinned LT | FR-028 open on `db_worker`→`db` once ASG SG wiring + IAM flows ship |

On **Action v0.32.0** the parser still builds VM/ASG elements and FR-034
drivers, but it does **not** attach instance-profile IAM to S3/RDS flows; CI
expected rows for those rules are unchanged. Plan warnings include
`no mapping for aws_iam_instance_profile.*` (supporting resources, not DFD
elements).

**Action v0.33.0 or later** (after the public client release that adds B-14 R1)
is required before asserting the new FR-032 / FR-028 flow rows and
`dfd_evidence` ids `vm-s3-resource-scoped` and `asg-db-scope-account` in
`expected/findings.json` (committed via `scripts/client-release.sh
--coverage-expected` with the pin bump).

### DynamoDB fixtures (B-14 R2 prep)

Plan-only tables `aws_dynamodb_table.sessions` (provider deletion protection
**on**) and `aws_dynamodb_table.audit` (**off**), plus IAM on the existing app
ECS task role and a dedicated `aws_lambda_function.audit_writer` role.

| Resource | Intended coverage (Fray **Action v0.34.0+**) |
|----------|-----------------------------------------------|
| `aws_dynamodb_table.sessions` | FR-040 mitigated (`deletion_protection_enabled = true`) |
| `aws_dynamodb_table.audit` | FR-040 open |
| `aws_ecs_service.app` → `sessions` | FR-039 mitigated (task role scoped to sessions ARN + `index/*` only) |
| `aws_lambda_function.audit_writer` → `audit` | FR-039 open (`dynamodb:*` on `"*"` plus explicit audit ARN → account scope, audit named) |

On **Action v0.33.2** the client does not map `aws_dynamodb_table` yet; the plan
emits `no mapping for aws_dynamodb_table.*; skipped` warnings only. **No new
expected rows** until the workflow pin reaches v0.34.0 and
`expected/findings.json` is updated (FR-039/FR-040 flow rows,
`sessions-scoped` / `audit-account` `dfd_evidence`).

### REST API Gateway fixtures (B-05 prep)

Section **(o)** in `infra/main.tf`: five REST APIs (`f51_open`, `f51_vpce`,
`f51_ip`, `f51_private`, `f51_cross`) with MOCK integrations and method
authorization `AWS_IAM`, plus a shared execute-api interface VPC endpoint and
security group. Inline policies use `Resource = "execute-api:/*"` (not the API
execution ARN).

| Resource | Policy shape |
|----------|----------------|
| `aws_api_gateway_rest_api.f51_open` | Allow `*` invoke, no conditions |
| `aws_api_gateway_rest_api.f51_vpce` | Allow `*` + Deny unless `aws:SourceVpce` |
| `aws_api_gateway_rest_api.f51_ip` | Allow `*` + Deny `NotIpAddress` on `aws:SourceIp` |
| `aws_api_gateway_rest_api.f51_private` | **PRIVATE** + same VPCE + Allow `*` + VPCE Deny |
| `aws_api_gateway_rest_api.f51_cross` | No inline policy; `aws_api_gateway_rest_api_policy.f51_cross` Allow foreign root `444455556666` |

### OpenAPI body fixtures (B-06)

Section **(p)** in `infra/main.tf`: six API Gateway APIs defined only by an
OpenAPI **3.0.1** document in `body` (`jsonencode`); no separate method or
route resources; no resource policy; MOCK integrations live in the spec.

| Resource | Auth in OpenAPI body | Action **v0.40.0** (current pin) | After next client pin (body auth) |
|----------|----------------------|----------------------------------|-----------------------------------|
| `aws_api_gateway_rest_api.f06_rest_public` | None (open GET /health) | FR-001 **unverified** (body not read for auth) | FR-001 **open** |
| `aws_api_gateway_rest_api.f06_rest_iam` | Global IAM SigV4 scheme | FR-001 **unverified** | FR-001 **mitigated** |
| `aws_api_gateway_rest_api.f06_rest_apikey` | API key required only | FR-001 **unverified** | FR-001 **open** (key is not caller identity) |
| `aws_api_gateway_rest_api.f06_rest_custom` | Lambda TOKEN authorizer | FR-001 **unverified** | FR-001 **unverified** (custom authorizer) |
| `aws_apigatewayv2_api.f06_http_public` | None | FR-001 **unverified** | FR-001 **open** |
| `aws_apigatewayv2_api.f06_http_jwt` | JWT authorizer | FR-001 **unverified** | FR-001 **mitigated** |

REST rows also carry **FR-051 mitigated** (no resource policy) and **FR-026
mitigated** (TLS edge) on the current pin.

### Known gaps

Until Action v0.33.0: no expected rows for VM/ASG IAM-derived S3 or RDS flows
(B-14 R1 client).

### Known incidental opens

Fixture noise that must stay open in SARIF but is not a coverage target.
Listed under `known_incidental` in `expected/findings.json` (exact-set assert).

| Rule | Address | Why |
|------|---------|-----|
| FR-005 | `aws_ecs_service.app` | Mutable `nginx:1.27` tag |
| FR-005 | `aws_ecs_service.worker` | Mutable `nginx:1.27` tag |
| FR-005 | `aws_ecs_service.declared` | Mutable `nginx:1.27` tag |
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
| `findings.json` | All findings: `rule_id`, `target` (DFD id), `status`, `severity`, optional local `addresses` (fray v0.27.0+) |
| `findings.sarif` | **Open** findings only; `partialFingerprints["fray/v1"]` = `sha256("<rule_id>\|<cause address>")` |
| `threat-model.md` | Human report |
| `pr-comment.md` | PR comment body |
| `payload.json` | Exact POST body when `show-payload: true` (redacted DFD) |
| `enrollment.json` | Enrollment soft-skip marker only |
| `base-source/` | Base-commit tree when comparing a PR |

`scripts/assert-findings.sh`:

1. **Open (coverage):** SARIF fingerprint present (`match: rule` still accepts any fingerprint for that rule id).
2. **Exact open set:** every SARIF open is an expected open or `known_incidental`.
3. **Mitigated / unverified / waived:** status counts in `findings.json`, and each expected address must appear in a matching finding’s `addresses` list. `address` on a flow row is the **To-element**.
4. **DFD evidence:** `payload.json` flows/elements carry the attributes that drive mitigated/open drivers (`authz_scope`, `region`, kinds).

### Fingerprints (`fray/v1`)

The client uses one function for every open finding (`render/sarif.go` `Fingerprint`, called with `CauseAddress`):

`sha256("<rule_id>|<cause Terraform address>")`

`CauseAddress` (`render/comment.go`) is the Terraform address that set the failing attribute when that cause is recorded, otherwise the target’s own address.

**Element rows** omit `flow`. The cause is the element address (first evidence address), so the script hashes `rule|address`. Example: `FR-036|aws_s3_bucket.uploads`.

**Flow rows** set `flow`. The hashed cause is often **not** the from or to address. `CauseAddress` reads `flow.Causes[<failed attribute>]` (in-memory only; `Causes` is not in the DFD JSON). When that is set, put it in `flow.cause`. If `cause` is omitted, the script uses `flow.to`, then `flow.from` (`defaultCause`: To-element, then From-element). `address` stays the To-element for membership checks. `from`, `to`, and `data_class` name the edge (`aws_ecs_service.worker` → `aws_db_instance.main`, `data_class` `unknown`).

FR-028 on that edge fails `authz_scope`. The cause is `data.aws_iam_policy_document.worker_rds`, so the input string is `FR-028|data.aws_iam_policy_document.worker_rds` (not `rule|from|to|data_class` and not the flow id).

**`match: rule`** is still right when the cause is not a Terraform address you can name, for example a signal address such as FR-017 (`signal:iam_service:bedrock`). Any open SARIF result with that rule id counts.

Mitigated, unverified and waived results are checked by Terraform address (`findings.json` `addresses`, fray v0.27.0+).

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
