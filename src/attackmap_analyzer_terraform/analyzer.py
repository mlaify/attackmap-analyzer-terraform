"""Terraform / HCL infrastructure-as-code analyzer for AttackMap.

This analyzer is shaped differently from language analyzers — Terraform doesn't
have routes in the application sense. Instead, the value is in:

- **Public ingress** — security groups / NACLs / Lambda function URLs / API
  Gateway methods with no auth → `entrypoint_hints`
- **Asset inventory** — S3 buckets, RDS, DynamoDB, Cognito user pools, KMS keys
  → `service_hints` and `database_hints`
- **Secrets** — `aws_secretsmanager_secret`, `aws_ssm_parameter` (SecureString),
  `variable` blocks marked `sensitive = true` or with secret-shaped names
  → `secret_hints`
- **IAM blast radius** — wildcards in policy actions (`Action: *`) → `auth_hints`
  with low confidence (broad permissions)
- **Database engines** — `aws_db_instance.engine = "postgres"` → `database_hints`
  with the engine as the kind

All emissions populate Signal v2 fields (line numbers, evidence snippets) so
downstream insights can cite `infra/main.tf:NN`.

HCL parsing uses brace-depth counting on top of regex. This is approximate but
sufficient for the resource-level introspection the analyzer needs. Variable
interpolation (`${var.foo}`) is not resolved — string literals and direct
attribute values are what we extract.
"""

from __future__ import annotations

import re
from pathlib import Path

from .contracts import (
    AnalyzerMetadata,
    AuthHint,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    Route,
    ScanResult,
    SecretHint,
    ServiceHint,
)

CODE_SUFFIXES = {".tf", ".tf.json", ".tfvars"}
SKIP_DIRS = {".terraform", ".git", "node_modules", "vendor"}
_SNIPPET_MAX_CHARS = 160

# ---------- Patterns ----------

# Top-level resource block header: resource "type" "name" {
RESOURCE_BLOCK_PATTERN = re.compile(
    r'\bresource\s+"([a-z][a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"\s*\{',
)
# Top-level variable block header: variable "name" {
VARIABLE_BLOCK_PATTERN = re.compile(
    r'\bvariable\s+"([a-zA-Z0-9_-]+)"\s*\{',
)
# Top-level data source: data "type" "name" {
DATA_BLOCK_PATTERN = re.compile(
    r'\bdata\s+"([a-z][a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"\s*\{',
)
# Module block: module "name" {
MODULE_BLOCK_PATTERN = re.compile(
    r'\bmodule\s+"([a-zA-Z0-9_-]+)"\s*\{',
)
# Provider declaration: provider "aws" { ... }
PROVIDER_BLOCK_PATTERN = re.compile(
    r'\bprovider\s+"([a-z][a-z0-9_]+)"\s*\{',
)

# Common attribute extraction inside block bodies
_ATTR_RE = re.compile(r'^\s*(\w+)\s*=\s*(.+?)\s*$', re.MULTILINE)


def _line_of(content: str, offset: int) -> int:
    if offset <= 0:
        return 1
    return content.count("\n", 0, offset) + 1


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    line = content[line_start:line_end].strip()
    if len(line) > max_chars:
        line = line[: max_chars - 1] + "…"
    return line


def _block_body(content: str, body_start: int) -> tuple[str, int]:
    """Return the body of a block whose `{` is at body_start-1, plus the offset
    of the closing `}`. Tracks brace depth and string literals so nested
    `ingress { ... }` blocks are included."""
    depth = 1
    i = body_start
    in_string = False
    escape = False
    while i < len(content) and depth > 0:
        ch = content[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[body_start:i], i
        i += 1
    return content[body_start:i], i


def _extract_attr(body: str, name: str) -> str | None:
    """Return the value of a top-level attribute `name = ...` in a block body
    (does not descend into nested blocks). Strips matching quotes."""
    pattern = re.compile(rf'^\s*{re.escape(name)}\s*=\s*"([^"]*)"\s*$', re.MULTILINE)
    match = pattern.search(body)
    if match:
        return match.group(1)
    # Try unquoted form (booleans, references, numbers, lists)
    raw_pattern = re.compile(rf'^\s*{re.escape(name)}\s*=\s*([^\n]+?)\s*$', re.MULTILINE)
    match = raw_pattern.search(body)
    if match:
        return match.group(1).strip()
    return None


def _has_open_cidr(body: str) -> bool:
    """True if the body references an open CIDR (`0.0.0.0/0` or `::/0`)
    as a list element."""
    return '"0.0.0.0/0"' in body or '"::/0"' in body


def _has_iam_wildcard_action(body: str) -> bool:
    """Detect IAM policy bodies with wildcard `Action` or `Resource`."""
    if '"Action": "*"' in body or '"Action":"*"' in body:
        return True
    if re.search(r'"Action"\s*:\s*\[\s*"\*"\s*\]', body):
        return True
    if re.search(r'Action\s*=\s*\[\s*"\*"\s*\]', body):
        return True
    if re.search(r'Action\s*=\s*"\*"', body):
        return True
    return False


# Provider/framework labels — used both as framework_hints and to gate cloud-specific extractors.
_PROVIDER_LABEL = {
    "aws": "terraform-aws",
    "azurerm": "terraform-azure",
    "google": "terraform-gcp",
    "kubernetes": "terraform-kubernetes",
}


# Database engine inference for aws_db_instance / aws_rds_cluster
_ENGINE_KIND_MAP = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "aurora-postgresql": "postgresql",
    "mysql": "mysql",
    "aurora-mysql": "mysql",
    "mariadb": "mariadb",
    "oracle-ee": "oracle",
    "oracle-se": "oracle",
    "oracle-se2": "oracle",
    "sqlserver-ee": "sqlserver",
    "sqlserver-se": "sqlserver",
    "sqlserver-ex": "sqlserver",
    "sqlserver-web": "sqlserver",
}


_SECRET_KEYWORDS = ("secret", "token", "key", "password", "pass", "pwd", "credential", "apikey")


def _looks_secret_shaped(name: str) -> bool:
    lowered = name.lower()
    return any(kw in lowered for kw in _SECRET_KEYWORDS)


class TerraformAnalyzer:
    metadata = AnalyzerMetadata(
        name="terraform",
        display_name="Terraform / HCL Analyzer",
        version="0.1.0",
        description="Terraform infrastructure-as-code analyzer covering AWS, Azure, and GCP resources, IAM wildcards, open security groups, and secrets.",
        scope="Terraform / OpenTofu projects (.tf files). Detects provider-level resources, public ingress, secret resources, and database engines.",
        targets=["terraform", "iac", "hcl", "aws", "azure", "gcp"],
        languages=["hcl"],
        priority=20,
        experimental=False,
        enabled_by_default=True,
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix == ".tf" or path.name.endswith(".tf.json") or path.suffix == ".tfvars":
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in SKIP_DIRS for part in file_path.parts):
                continue
            if not (file_path.suffix == ".tf" or file_path.name.endswith(".tf.json") or file_path.suffix == ".tfvars"):
                continue

            result.files_scanned += 1
            if "hcl" not in result.languages:
                result.languages.append("hcl")

            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            relative = str(file_path.relative_to(root))
            self._extract_providers(content, relative, result)
            self._extract_resources(content, relative, result)
            self._extract_variables(content, relative, result)
            self._extract_modules(content, relative, result)
            self._extract_data_sources(content, relative, result)

        result.languages.sort()
        return result

    # ---------- Extractors ----------

    def _extract_providers(self, content: str, relative: str, result: ScanResult) -> None:
        for match in PROVIDER_BLOCK_PATTERN.finditer(content):
            provider = match.group(1)
            label = _PROVIDER_LABEL.get(provider, f"terraform-{provider}")
            self._append_unique_framework(
                result, label, relative,
                _line_of(content, match.start()),
                _line_snippet(content, match.start()),
            )

    def _extract_resources(self, content: str, relative: str, result: ScanResult) -> None:
        for match in RESOURCE_BLOCK_PATTERN.finditer(content):
            resource_type, resource_name = match.group(1), match.group(2)
            body, _ = _block_body(content, match.end())
            line = _line_of(content, match.start())
            self._dispatch_resource(resource_type, resource_name, body, relative, line, content, match.start(), result)

    def _extract_variables(self, content: str, relative: str, result: ScanResult) -> None:
        for match in VARIABLE_BLOCK_PATTERN.finditer(content):
            var_name = match.group(1)
            body, _ = _block_body(content, match.end())
            line = _line_of(content, match.start())
            sensitive = (_extract_attr(body, "sensitive") or "").lower() == "true"
            if sensitive or _looks_secret_shaped(var_name):
                self._append_unique_secret(
                    result, var_name, relative, line,
                    _line_snippet(content, match.start()),
                )

    def _extract_modules(self, content: str, relative: str, result: ScanResult) -> None:
        for match in MODULE_BLOCK_PATTERN.finditer(content):
            module_name = match.group(1)
            self._append_unique_service(result, f"module:{module_name}", relative)

    def _extract_data_sources(self, content: str, relative: str, result: ScanResult) -> None:
        # data "aws_secretsmanager_secret" "x" { ... } — surface secret references via data.
        for match in DATA_BLOCK_PATTERN.finditer(content):
            data_type, data_name = match.group(1), match.group(2)
            line = _line_of(content, match.start())
            if data_type in {"aws_secretsmanager_secret", "aws_secretsmanager_secret_version", "aws_ssm_parameter"}:
                self._append_unique_secret(
                    result, f"data:{data_type}:{data_name}", relative, line,
                    _line_snippet(content, match.start()),
                )

    # ---------- Resource dispatchers ----------

    def _dispatch_resource(
        self,
        resource_type: str,
        resource_name: str,
        body: str,
        file: str,
        line: int,
        content: str,
        offset: int,
        result: ScanResult,
    ) -> None:
        ev = _line_snippet(content, offset)

        # ---- AWS ----
        if resource_type == "aws_security_group" and _has_open_cidr(body):
            self._append_unique_entrypoint(
                result, f"sg_open_ingress:{resource_name}", file, line, ev,
            )
            return
        if resource_type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"} and _has_open_cidr(body):
            direction = (_extract_attr(body, "type") or "").lower() or "ingress"
            self._append_unique_entrypoint(
                result, f"sg_rule_{direction}_open:{resource_name}", file, line, ev,
            )
            return
        if resource_type == "aws_lambda_function":
            self._append_unique_entrypoint(
                result, f"lambda:{resource_name}", file, line, ev,
            )
            self._append_unique_service(result, f"function:{resource_name}", file)
            return
        if resource_type == "aws_lambda_function_url":
            authorization_type = (_extract_attr(body, "authorization_type") or "").upper()
            label = "lambda_url_open" if authorization_type == "NONE" else "lambda_url"
            self._append_unique_entrypoint(
                result, f"{label}:{resource_name}", file, line, ev,
            )
            return
        if resource_type == "aws_api_gateway_method":
            http_method = (_extract_attr(body, "http_method") or "ANY").upper()
            authorization = (_extract_attr(body, "authorization") or "").upper()
            if authorization == "NONE":
                self._append_unique_entrypoint(
                    result, f"apigw_open_method:{http_method}:{resource_name}", file, line, ev,
                )
            else:
                self._append_unique_entrypoint(
                    result, f"apigw_method:{http_method}:{resource_name}", file, line, ev,
                )
            return
        if resource_type == "aws_apigatewayv2_route":
            route_key = _extract_attr(body, "route_key") or ""
            authorization_type = (_extract_attr(body, "authorization_type") or "").upper()
            if route_key:
                # route_key is "GET /users" or "POST /things" — split into method + path.
                parts = route_key.strip().split(maxsplit=1)
                if len(parts) == 2:
                    method, path = parts[0].upper(), parts[1]
                    self._append_unique_route(result, path, method, file, line)
                    if authorization_type == "NONE":
                        self._append_unique_entrypoint(
                            result, f"apigwv2_open:{resource_name}", file, line, ev,
                        )
            return
        if resource_type in {"aws_lb", "aws_alb", "aws_cloudfront_distribution"}:
            self._append_unique_entrypoint(
                result, f"{resource_type}:{resource_name}", file, line, ev,
            )
            return
        if resource_type == "aws_s3_bucket":
            self._append_unique_service(result, f"s3_bucket:{resource_name}", file)
            return
        if resource_type == "aws_s3_bucket_acl":
            acl = (_extract_attr(body, "acl") or "").lower()
            if acl in {"public-read", "public-read-write"}:
                self._append_unique_entrypoint(
                    result, f"s3_public_acl:{resource_name}", file, line, ev,
                )
            return
        if resource_type == "aws_s3_bucket_public_access_block":
            for attr in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                value = (_extract_attr(body, attr) or "true").lower()
                if value == "false":
                    self._append_unique_entrypoint(
                        result, f"s3_public_block_disabled:{resource_name}", file, line, ev,
                    )
                    return
            return
        if resource_type == "aws_db_instance" or resource_type == "aws_rds_cluster":
            engine = (_extract_attr(body, "engine") or "").lower()
            kind = _ENGINE_KIND_MAP.get(engine, "sql")
            self._append_unique_database(result, kind, file, line, ev)
            self._append_unique_service(result, f"rds:{resource_name}", file)
            publicly_accessible = (_extract_attr(body, "publicly_accessible") or "false").lower()
            if publicly_accessible == "true":
                self._append_unique_entrypoint(
                    result, f"rds_publicly_accessible:{resource_name}", file, line, ev,
                )
            return
        if resource_type in {"aws_dynamodb_table", "aws_dynamodb_global_table"}:
            self._append_unique_database(result, "dynamodb", file, line, ev)
            self._append_unique_service(result, f"dynamodb:{resource_name}", file)
            return
        if resource_type in {"aws_elasticache_cluster", "aws_elasticache_replication_group"}:
            self._append_unique_database(result, "redis", file, line, ev)
            self._append_unique_service(result, f"elasticache:{resource_name}", file)
            return
        if resource_type in {"aws_documentdb_cluster", "aws_docdb_cluster"}:
            self._append_unique_database(result, "mongodb", file, line, ev)
            return
        if resource_type == "aws_secretsmanager_secret":
            self._append_unique_secret(result, f"secretsmanager:{resource_name}", file, line, ev)
            return
        if resource_type == "aws_ssm_parameter":
            param_type = (_extract_attr(body, "type") or "").lower()
            if param_type == "securestring":
                self._append_unique_secret(result, f"ssm:{resource_name}", file, line, ev)
            return
        if resource_type == "aws_kms_key" or resource_type == "aws_kms_alias":
            self._append_unique_service(result, f"kms:{resource_name}", file)
            return
        if resource_type == "aws_cognito_user_pool":
            self._append_unique_auth(result, f"cognito_user_pool:{resource_name}", file, line, ev, 0.85)
            return
        if resource_type in {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"}:
            if _has_iam_wildcard_action(body):
                self._append_unique_auth(
                    result, f"iam_wildcard_action:{resource_name}", file, line, ev, 0.7,
                )
            return

        # ---- Azure ----
        if resource_type == "azurerm_storage_account":
            self._append_unique_service(result, f"azure_storage:{resource_name}", file)
            return
        if resource_type == "azurerm_key_vault":
            self._append_unique_service(result, f"key_vault:{resource_name}", file)
            return
        if resource_type == "azurerm_network_security_rule" and _has_open_cidr(body):
            self._append_unique_entrypoint(
                result, f"azure_nsg_open:{resource_name}", file, line, ev,
            )
            return
        if resource_type in {"azurerm_postgresql_server", "azurerm_postgresql_flexible_server"}:
            self._append_unique_database(result, "postgresql", file, line, ev)
            return
        if resource_type in {"azurerm_mysql_server", "azurerm_mysql_flexible_server"}:
            self._append_unique_database(result, "mysql", file, line, ev)
            return
        if resource_type == "azurerm_cosmosdb_account":
            self._append_unique_database(result, "cosmosdb", file, line, ev)
            return

        # ---- GCP ----
        if resource_type == "google_storage_bucket":
            self._append_unique_service(result, f"gcs_bucket:{resource_name}", file)
            return
        if resource_type == "google_compute_firewall" and _has_open_cidr(body):
            self._append_unique_entrypoint(
                result, f"gcp_firewall_open:{resource_name}", file, line, ev,
            )
            return
        if resource_type == "google_sql_database_instance":
            db_version = (_extract_attr(body, "database_version") or "").lower()
            kind = "sql"
            if "postgres" in db_version:
                kind = "postgresql"
            elif "mysql" in db_version:
                kind = "mysql"
            elif "sqlserver" in db_version:
                kind = "sqlserver"
            self._append_unique_database(result, kind, file, line, ev)
            return

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(result: ScanResult, path: str, method: str, file: str, line: int | None) -> None:
        key = (path, method, file)
        if any((item.path, item.method, item.file) == key for item in result.routes):
            return
        result.routes.append(Route(path=path, method=method, file=file, line=line))

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if any((item.kind, item.file) == key for item in result.databases):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.auth_hints):
            return
        result.auth_hints.append(AuthHint(hint=hint, file=file, line=line, evidence_text=evidence, confidence=confidence))

    @staticmethod
    def _append_unique_secret(result: ScanResult, name: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        result.secret_hints.append(SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85))

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if any((item.target, item.file) == key for item in result.external_calls):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.framework_hints):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.entrypoint_hints):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if any((item.hint, item.file) == key for item in result.service_hints):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["TerraformAnalyzer"]
