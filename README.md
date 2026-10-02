# attackmap-analyzer-terraform

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Terraform / HCL infrastructure-as-code analyzer for [AttackMap](https://github.com/mlaify/AttackMap).

This analyzer is shaped differently from language analyzers — Terraform doesn't have routes in the application sense. Instead, it extracts:

- **Public ingress** — security groups (`ingress` blocks only; open egress is ignored) and inbound firewall rules with `0.0.0.0/0` / `::/0`, Lambda Function URLs with no auth, API Gateway methods with `authorization = "NONE"`, S3 buckets with public ACLs (inline or `aws_s3_bucket_acl`), public bucket policies or disabled public-access blocks → `entrypoint_hints`
- **Asset inventory** — S3 buckets, Azure storage accounts, GCS buckets, KMS keys, Cognito user pools → `service_hints`
- **Databases** — `aws_db_instance` and `aws_rds_cluster` (engine-aware: postgres / mysql / oracle / sqlserver / mariadb), `aws_dynamodb_table`, `aws_elasticache_*`, `aws_documentdb_*`, Azure PostgreSQL/MySQL/CosmosDB, GCP Cloud SQL → `database_hints`
- **Secrets** — `aws_secretsmanager_secret`, `aws_ssm_parameter` (SecureString), `azurerm_key_vault`, plus `variable` blocks marked `sensitive = true` or with secret-shaped names (`*secret*`, `*token*`, `*password*`, `*key*`), and secret-shaped string literals in `.tfvars` (`kind="hardcoded"`) → `secret_hints`
- **IAM blast radius** — Allow statements with `Action "*"` (0.7), `Resource "*"` (0.5) or unconditioned `Principal "*"` (0.7) in `aws_iam_*_policy`, `aws_iam_role` trust/inline policies and `data "aws_iam_policy_document"` → `auth_hints`
- **Cognito** — `aws_cognito_user_pool` → `auth_hints`
- **Modules** — `module "x" { source = ... }` → `service_hints` keyed `module:x`
- **API Gateway v2 routes** — `aws_apigatewayv2_route` with `route_key = "POST /charges"` → actual `Route` entries

All emissions populate AttackMap's Signal v2 fields (line numbers + evidence snippets) so downstream insights can cite `infra/main.tf:NN`.

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-terraform.git
```

The analyzer is auto-discovered by AttackMap via the `attackmap.analyzers` entry-point group.

## Usage with AttackMap

```bash
# Auto-discovered when installed:
attackmap analyze /path/to/terraform/repo

# Or invoke explicitly:
attackmap analyze /path/to/terraform/repo --module terraform
```

## Detection

`detect()` returns true when any `.tf`, `.tf.json`, or `.tfvars` file is present in the tree, ignoring `.terraform/` and AttackMap's shared skip list (`.git/`, `node_modules/`, `vendor/`, `build/`, `dist/`, `out/`, `target/`, ...). Skip directories are matched only *inside* the repo, so a checkout under e.g. `/build/...` is still scanned. Files are walked with `attackmap.sdk.iter_repo_files`, which does not follow symlinks out of the repo.

## HCL block parsing

The analyzer parses HCL block bodies via brace-depth counting (with string-literal awareness so `"{" inside strings"` doesn't throw off the counter). Nested blocks like multiple `ingress { }` blocks inside a security group are handled correctly. **Variable interpolation** (`${var.foo}`, `aws_iam_role.app.id`) is **not resolved** — string literals and direct attribute values are what get extracted.

## Coverage notes

- **AWS** is the most thoroughly covered provider. Azure and GCP have basic coverage (NSG/firewall open ingress, Storage Account / GCS bucket as service hints, PostgreSQL/MySQL/CosmosDB/CloudSQL as databases) — extend per resource type as needed.
- **IAM wildcard detection** matches JSON-shaped (`"Action": "*"`, heredoc or `.tf.json` string) and HCL-shaped (`Action = "*"` in `jsonencode`, `actions = ["*"]` in `aws_iam_policy_document`) policies. A `policy = data.aws_iam_policy_document.x.json` reference isn't followed; the data source is reported under its own name.
- **`.tf.json`** files get the same analysis as `.tf`. **`.tfvars`** files are checked for secret-shaped string literals (reported as `kind="hardcoded"` with the value redacted).
- **API Gateway v1** routing is partial — only individual `aws_api_gateway_method` resources emit entrypoint hints. Path joining across `aws_api_gateway_resource` chains is not yet implemented (use API Gateway v2 / `aws_apigatewayv2_route` for full path+method extraction).
- **Lambda Function URLs** with `authorization_type = "NONE"` are flagged as open entrypoints. IAM-authorized URLs are emitted with the regular `lambda_url:` prefix.
- **Database `publicly_accessible = true`** on `aws_db_instance` produces a separate `rds_publicly_accessible:` entrypoint hint in addition to the standard database hint.

## License

MIT
