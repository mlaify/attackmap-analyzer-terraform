# Changelog

All notable changes to `attackmap-analyzer-terraform` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Misconfigurations become core findings (#4, AttackMap#334).** Risky settings are emitted as `CloudMisconfig` records in `cloud_misconfigs`, which core turns into findings with CWE/OWASP/ATT&CK ids. Existing entrypoint/auth hints are unchanged. New and newly reported checks:
  - Module sources: git sources without `?ref=` or pinned to a branch, and registry modules without `version` (`iac_module_unpinned`). Tags and commit SHAs count as pinned.
  - `associate_public_ip_address = true` on instances, launch configurations and launch templates. Public EKS API endpoints (explicit or by default). `aws_lb_listener` on HTTP without a redirect (internal load balancers are skipped). API Gateway v1 `NONE` methods without an API key and v2 HTTP routes without `authorization_type` (defaults to `NONE`), with `OPTIONS` skipped. `storage_encrypted = false` (or unset on `aws_db_instance`). OpenSearch / Elasticsearch access policies open to `Principal "*"`.
  - GCP: Cloud Run / Cloud Functions invokers and GCS buckets granted to `allUsers` / `allAuthenticatedUsers`. Azure: `public_network_access_enabled = true`, `allow_nested_items_to_be_public = true`, public storage containers.
  - kubernetes provider: privileged / privilege-escalating containers, host namespaces, `host_path` volumes, `cluster-admin` and broad-group bindings, wildcard / escalating / Secret-reading roles, and `LoadBalancer` / `NodePort` services without source ranges.
  - Public S3 ACLs and policies, disabled public-access blocks, public RDS and `NONE` Lambda function URLs (already entrypoint hints) are reported as records too.
- **Review round 1 fixes (#4).**
  - **Hostile input is linear.** Top-level blocks are scanned on from the end of the previous one, so 30000 unterminated `resource {` take 0.4 s (was >60 s). IAM policy statements are looked for only up to brace depth 8, so 100000 nested `{` take 0.2 s (was >60 s). Signal dedup uses key sets, and line numbers come from a cached per-file index: 40000 modules take 0.8 s (was 52 s) and 20000 records 1.7 s (was 18 s).
  - **Comments, strings and heredocs** don't count when finding block bounds, and an unterminated block no longer hides later blocks. IAM policy statement scanning uses the same heredoc mode for depth and body scans, so `{ <<EOF\n}\nEOF` repeated inside `jsonencode(` is linear (112 KB took over 60 s).
  - **HTTP listeners.** `aws_lb.x[0].arn` / `["k"]` references resolve. `internal` is looked up per module directory. A `dynamic "default_action"` is judged by its `content`, and a computed action type or `internal` value isn't reported. A listener whose load balancer can't be resolved gets confidence 0.6.
  - **Secret variable defaults** are judged by value too. SSH/PEM public keys, URLs without an embedded password, values under 6 characters, plain words (`UserId`, `master`, `off`) and username-like variables aren't hard-coded secrets.
  - **kubernetes provider.**
    - RBAC wildcards only on control-plane API groups and `*`/sensitive resources (not `events`, not `metrics.k8s.io`); `resource_names` narrows Secret reads.
    - `system:authenticated` & co. are reported only when bound to `cluster-admin`/`admin`/`edit`.
    - Internal-LB annotations are judged by value (`aws-load-balancer-internal = "false"` and `scheme = "internet-facing"` are exposed).
    - CA/TLS certs, `/etc/letsencrypt`, `/dev/log` and `/dev/dri` host paths are low.
  - **API Gateway v2 `$default`.** The catch-all route on an HTTP API is an `ANY /{proxy+}` route and, without an authorizer, an `api_no_authorizer` record. WebSocket `$default` routes are skipped.
  - **Feature detection.** Records are emitted only when the core exports `CloudMisconfig` and `ScanResult` has `cloud_misconfigs`. The pre-existing exposure hints are emitted on every core.
- **`for_each` / `count` and module provenance.** Records carry the resource's `for_each` / `count` in `context`, and hint evidence gets a `[for_each = ...]` suffix. Resources in a local module (`source = "./modules/x"`) are attributed to the `module.<name> (file:line)` blocks that call it.
- **Secret variable defaults.** A `sensitive` or secret-named `variable` with a literal string `default` is `SecretHint(kind="hardcoded")` (the value is redacted). Bare declarations are unchanged.
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

- **License metadata uses an SPDX expression (PEP 639).** `license = "MIT"` and `license-files = ["LICENSE"]` replace the deprecated `license = {text = "MIT"}` table, and the `License ::` classifier (which setuptools ≥ 77 rejects next to an expression) is gone. The build backend floor is now `setuptools>=77` (mlaify/AttackMap#259).
- **Import the analyzer contract from `attackmap.sdk` directly; `contracts.py` is gone.** It only re-exported SDK types (and aliased `AnalyzerProtocol` as `AttackMapAnalyzerProtocol`), and its four copy-pasted variants drifted across the plugins (mlaify/AttackMap#259).
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
