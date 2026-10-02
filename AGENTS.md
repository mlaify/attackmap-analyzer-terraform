# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

## Scope
Terraform / HCL infrastructure-as-code coverage:

- **Public ingress**: AWS security groups with open CIDRs in an `ingress` block (open `egress` is not reported) + ingress security-group rules with open CIDRs, Lambda Function URLs with `authorization_type = "NONE"`, API Gateway v1 `aws_api_gateway_method` with `authorization = "NONE"`, API Gateway v2 routes with no auth, S3 buckets with public ACLs (inline `acl` or `aws_s3_bucket_acl`), Allow-`Principal "*"` bucket policies without a `Condition` (inline `policy` or `aws_s3_bucket_policy`), or disabled public-access blocks, RDS with `publicly_accessible = true`, inbound Azure NSG rules with `0.0.0.0/0`, ingress GCP firewalls with open `source_ranges`
- **Asset inventory**: AWS S3 buckets / KMS keys / Cognito user pools, Azure Storage Accounts / Key Vaults, GCS buckets — emitted as `service_hints`
- **Databases**: AWS RDS (engine-aware), DynamoDB, ElastiCache (Redis), DocumentDB (Mongo), Azure PostgreSQL / MySQL / CosmosDB, GCP Cloud SQL (`database_version`-aware)
- **Secrets**: `aws_secretsmanager_secret`, `aws_ssm_parameter` (SecureString only), `data` lookups for either, `variable` blocks marked `sensitive = true` or with secret-shaped names, secret-shaped `key = "literal"` assignments in `.tfvars` (`SecretHint(kind="hardcoded")`; the literal is never echoed into evidence; identifier-shaped keys like `kms_key_id` / `ssh_key_name` are skipped)
- **IAM wildcards**: Allow statements in `aws_iam_*_policy` / `aws_iam_role` (trust + inline) bodies (`jsonencode`, heredoc JSON; keys case-insensitive) and `data "aws_iam_policy_document"` `statement { }` blocks → `iam_wildcard_action` (`Action "*"`), `iam_wildcard_resource` (`Resource "*"`), `iam_wildcard_principal` (`Principal "*"` with no `Condition`). Deny statements are ignored. Service wildcards such as `s3:*` are not flagged.
- **Terraform JSON**: `.tf.json` is parsed with `json`; each block is rendered back to HCL and routed through the same handlers as `.tf` (identical signals), with `file:line` pointing at the JSON source.
- **API Gateway v2 routes**: `route_key = "POST /charges"` → `Route` with method+path

## Out of scope (for now)
- Variable interpolation resolution (`${var.foo}`, `aws_iam_role.app.id`) — string literals and direct attribute values are what's extracted.
- API Gateway v1 path joining (`aws_api_gateway_resource` parent chains) — only individual methods are emitted.
- Following `policy = data.aws_iam_policy_document.x.json` references — the data source is flagged under its own name instead.
- `.tfvars.json` files.
- Module-level recursive analysis — modules are emitted as service hints; their referenced sources aren't followed.
- OpenTofu-only resource types not present in the AWS / Azure / GCP providers.

## HCL parsing approach
- Top-level resource/variable/module/data/provider headers are matched with regex.
- Block bodies are extracted by brace-depth counting (with string-literal awareness so `"{"` inside strings doesn't unbalance the counter). Nested blocks like multiple `ingress { ... }` inside a security group are handled correctly.
- Attribute extraction inside a body uses simple `^\s*name\s*=\s*"value"\s*$` (or unquoted) regex on the body's top level only (nested block / object contents are stripped first), so a nested `type = ...` can't shadow the resource's own.

## Confidence policy
- Cognito user pools (canonical AWS identity provider) → 0.85
- IAM wildcard actions / principals → 0.7 (broad permissions are a smell, not always a failure — could be infrastructure-bootstrap roles by design)
- IAM wildcard resources → 0.5 (`Resource "*"` with scoped actions is common, e.g. `ec2:Describe*`)
- All other emissions use the default confidence of the underlying hint type.

## Testing
Each new resource handler must include both:
- A positive test (resource fires the expected signal).
- A negative test (look-alike resource does NOT fire — e.g., `aws_ssm_parameter` with `type = "String"` is not a secret).

The brace-depth walker is exercised by `test_nested_blocks_do_not_break_extraction`, which puts an SG with multiple `ingress { }` blocks before a `aws_db_instance` and asserts both extract correctly.
