# Changelog

All notable changes to `attackmap-analyzer-terraform` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Routes carry their auth in the core contract (#8, AttackMap#256).** `Route.auth` is `required`, `anonymous` or `unknown`, with `guards` naming the authorizer type (and `authorizer_id`) and `guard_evidence` quoting the attribute lines. `AWS_IAM` / `COGNITO_USER_POOLS` / `CUSTOM` / `JWT` (and v1 `api_key_required = true`) are `required`. An explicit `"NONE"` is `anonymous`. An omitted or computed value is `unknown`. AttackMap ≥ 0.6 trusts this over its ±40-line auth-hint window. Older cores ignore the fields, and the `apigw_open_method:*` / `apigwv2_open:*` / `lambda_url_open:*` entrypoint hints are kept for one release.
- **API Gateway v1 methods are routes.** An `aws_api_gateway_method` whose `resource_id` resolves through literal `aws_api_gateway_resource` `parent_id` / `path_part` chains to the API's `root_resource_id` is emitted as a `Route` (e.g. `DELETE /orders/{id}`), resolved across files after the walk. Unresolvable ones keep only their entrypoint hint.
- **Lambda function URLs are routes.** Each `aws_lambda_function_url` is an `ANY /` `Route` carrying its `authorization_type`.

- `data "aws_iam_policy_document"` `statement { }` blocks are checked for wildcard `actions`, `resources` and `principals` (#3).
- `aws_iam_role` trust (`assume_role_policy`) and inline policies, and `aws_iam_group_policy`, are checked; Allow statements with `Principal "*"` and no `Condition` emit `iam_wildcard_principal:<name>` (#3).
- `Resource "*"` now emits `iam_wildcard_resource:<name>` (confidence 0.5), as the docs already claimed (#3).
- Inline `acl = "public-read"` on `aws_s3_bucket` (AWS provider <= v3) emits `s3_public_acl:<name>`; public bucket policies (inline `policy` or `aws_s3_bucket_policy`) emit `s3_public_policy:<name>` (#3).
- `.tfvars` secret-shaped string literals (`db_password = "..."`) emit `SecretHint(kind="hardcoded")`, with the value redacted from evidence (#3).
- `.tf.json` files are parsed as JSON and analyzed identically to `.tf`, with `file:line` pointing into the JSON source (#3).

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of a local `rglob` + `SKIP_DIRS` walk (mlaify/AttackMap#253).
- The skip list is now AttackMap's shared `DEFAULT_SKIP_DIRS` plus `.terraform/`, so `.tf` files under in-repo `build/`, `dist/`, `out/`, `target/`, `venv/` etc. directories are no longer scanned.

### Fixed

- `aws_security_group` with an open CIDR only in `egress` (the default) was reported as `sg_open_ingress`; only `ingress` blocks (including `dynamic "ingress"` and `ingress = [{...}]`) are checked now. Egress `aws_security_group_rule`s, outbound Azure NSG rules and `EGRESS` GCP firewalls are no longer reported as open (#3).
- IAM policy checks are statement-aware: `Deny` statements are ignored, keys are matched case-insensitively, and the old check that matched `Action = "*"` anywhere in the body is gone (#3).
- `_extract_attr` only reads a block's own top-level attributes, so e.g. a nested `type = ...` no longer shadows the resource's `type` (#3).
- A repo checked out under a directory named like a skip dir (e.g. `.../vendor/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo are no longer followed and analyzed.
- cp1252/latin-1 encoded files are analyzed instead of silently dropped, and an unreadable file no longer raises out of `analyze()`.
- `files_scanned` no longer counts files that could not be read.

## [0.1.0] - 2026-06-04

### Added

- Initial public release. Terraform / HCL infrastructure-as-code analyzer plugin for AttackMap (AWS, Azure, GCP resources; IAM wildcards; open security groups; secret resources).
- Registered under the `attackmap.analyzers` entry-point group so the core
  AttackMap CLI auto-discovers this analyzer once installed.
- Emits Signal-v2 records (`file:line` citation, evidence text, and confidence
  score) for every signal.

[Unreleased]: https://github.com/mlaify/attackmap-analyzer-terraform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mlaify/attackmap-analyzer-terraform/releases/tag/v0.1.0
