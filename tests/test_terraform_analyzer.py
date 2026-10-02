"""Tests for the TerraformAnalyzer plugin."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from attackmap_analyzer_terraform import TerraformAnalyzer


# ---------- detect() ----------


def test_detect_picks_up_tf_file(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('provider "aws" {}\n', encoding="utf-8")
    assert TerraformAnalyzer().detect(tmp_path) is True


def test_detect_picks_up_tfvars(tmp_path: Path) -> None:
    (tmp_path / "prod.tfvars").write_text('region = "us-east-1"\n', encoding="utf-8")
    assert TerraformAnalyzer().detect(tmp_path) is True


def test_detect_skips_terraform_dir(tmp_path: Path) -> None:
    (tmp_path / ".terraform").mkdir()
    (tmp_path / ".terraform" / "leftover.tf").write_text('# cached', encoding="utf-8")
    assert TerraformAnalyzer().detect(tmp_path) is False


def test_detect_returns_false_for_empty(tmp_path: Path) -> None:
    assert TerraformAnalyzer().detect(tmp_path) is False


# ---------- Provider detection ----------


def test_provider_aws_emits_framework(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n'
        '  region = "us-east-1"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(f.hint == "terraform-aws" for f in result.framework_hints)


def test_provider_azure_and_gcp(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'provider "azurerm" {}\nprovider "google" {}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    fw = {f.hint for f in result.framework_hints}
    assert "terraform-azure" in fw
    assert "terraform-gcp" in fw


# ---------- AWS security groups ----------


def test_security_group_with_open_ingress_emits_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "aws_security_group" "web" {\n'
        '  name = "web-sg"\n'
        '  ingress {\n'
        '    from_port   = 443\n'
        '    to_port     = 443\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    hints = {e.hint for e in result.entrypoint_hints}
    assert "sg_open_ingress:web" in hints

    web = next(e for e in result.entrypoint_hints if e.hint == "sg_open_ingress:web")
    assert web.line == 1
    assert web.evidence_text and "aws_security_group" in web.evidence_text


def test_security_group_without_open_cidr_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        'resource "aws_security_group" "internal" {\n'
        '  ingress {\n'
        '    cidr_blocks = ["10.0.0.0/8"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert not any("sg_open" in e.hint for e in result.entrypoint_hints)


# ---------- AWS lambda + API Gateway ----------


def test_lambda_function_url_with_no_auth(tmp_path: Path) -> None:
    (tmp_path / "lambda.tf").write_text(
        'resource "aws_lambda_function" "fn" {\n'
        '  function_name = "billing-fn"\n'
        '}\n'
        '\n'
        'resource "aws_lambda_function_url" "url" {\n'
        '  function_name      = aws_lambda_function.fn.function_name\n'
        '  authorization_type = "NONE"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    hints = {e.hint for e in result.entrypoint_hints}
    assert "lambda:fn" in hints
    assert "lambda_url_open:url" in hints


def test_apigatewayv2_route_extracts_method_and_path(tmp_path: Path) -> None:
    (tmp_path / "apigw.tf").write_text(
        'resource "aws_apigatewayv2_route" "create_user" {\n'
        '  api_id             = aws_apigatewayv2_api.api.id\n'
        '  route_key          = "POST /users"\n'
        '  authorization_type = "NONE"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    pairs = {(r.path, r.method) for r in result.routes}
    assert ("/users", "POST") in pairs
    hints = {e.hint for e in result.entrypoint_hints}
    assert "apigwv2_open:create_user" in hints


def test_api_gateway_method_with_authorizer_does_not_get_open_label(tmp_path: Path) -> None:
    (tmp_path / "apigw.tf").write_text(
        'resource "aws_api_gateway_method" "secure" {\n'
        '  http_method   = "POST"\n'
        '  authorization = "AWS_IAM"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    hints = {e.hint for e in result.entrypoint_hints}
    assert "apigw_method:POST:secure" in hints
    assert "apigw_open_method:POST:secure" not in hints


# ---------- AWS S3 ----------


def test_s3_bucket_with_public_acl_emits_open_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "demo-data"\n'
        '}\n'
        '\n'
        'resource "aws_s3_bucket_acl" "data_acl" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  acl    = "public-read"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    services = {h.hint for h in result.service_hints}
    assert "s3_bucket:data" in services

    eps = {e.hint for e in result.entrypoint_hints}
    assert "s3_public_acl:data_acl" in eps


def test_s3_public_access_block_disabled(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "weak" {\n'
        '  bucket                  = aws_s3_bucket.data.id\n'
        '  block_public_acls       = false\n'
        '  block_public_policy     = false\n'
        '  ignore_public_acls      = false\n'
        '  restrict_public_buckets = false\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    eps = {e.hint for e in result.entrypoint_hints}
    assert "s3_public_block_disabled:weak" in eps


# ---------- AWS RDS / DynamoDB / Redis ----------


def test_aws_db_instance_emits_correct_database_kind(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "main" {\n'
        '  engine          = "postgres"\n'
        '  instance_class  = "db.t3.micro"\n'
        '  allocated_storage = 20\n'
        '  publicly_accessible = true\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)
    eps = {e.hint for e in result.entrypoint_hints}
    assert "rds_publicly_accessible:main" in eps


def test_aws_dynamodb_table_emits_dynamodb(tmp_path: Path) -> None:
    (tmp_path / "ddb.tf").write_text(
        'resource "aws_dynamodb_table" "users" {\n'
        '  name         = "users"\n'
        '  billing_mode = "PAY_PER_REQUEST"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(d.kind == "dynamodb" for d in result.databases)


def test_aws_elasticache_emits_redis(tmp_path: Path) -> None:
    (tmp_path / "cache.tf").write_text(
        'resource "aws_elasticache_replication_group" "cache" {\n'
        '  replication_group_id = "cache"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(d.kind == "redis" for d in result.databases)


# ---------- Secrets ----------


def test_secretsmanager_secret_resource_emits_secret(tmp_path: Path) -> None:
    (tmp_path / "secrets.tf").write_text(
        'resource "aws_secretsmanager_secret" "stripe" {\n'
        '  name = "stripe-secret-key"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "secretsmanager:stripe" in names


def test_ssm_parameter_securestring_emits_secret(tmp_path: Path) -> None:
    (tmp_path / "ssm.tf").write_text(
        'resource "aws_ssm_parameter" "jwt" {\n'
        '  name  = "/app/jwt-secret"\n'
        '  type  = "SecureString"\n'
        '  value = "redacted"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "ssm:jwt" in names


def test_ssm_parameter_string_does_not_emit_secret(tmp_path: Path) -> None:
    (tmp_path / "ssm.tf").write_text(
        'resource "aws_ssm_parameter" "config" {\n'
        '  name  = "/app/region"\n'
        '  type  = "String"\n'
        '  value = "us-east-1"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert not any("ssm:config" in s.name for s in result.secret_hints)


def test_sensitive_variable_extracts_secret(tmp_path: Path) -> None:
    (tmp_path / "vars.tf").write_text(
        'variable "stripe_api_key" {\n'
        '  type      = string\n'
        '  sensitive = true\n'
        '}\n'
        '\n'
        'variable "region" {\n'
        '  type    = string\n'
        '  default = "us-east-1"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    names = {s.name for s in result.secret_hints}
    assert "stripe_api_key" in names
    assert "region" not in names


def test_secret_shaped_variable_name_extracts_secret(tmp_path: Path) -> None:
    (tmp_path / "vars.tf").write_text(
        'variable "jwt_signing_secret" {\n'
        '  type = string\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(s.name == "jwt_signing_secret" for s in result.secret_hints)


def test_data_aws_secretsmanager_picked_up(tmp_path: Path) -> None:
    (tmp_path / "data.tf").write_text(
        'data "aws_secretsmanager_secret" "stripe" {\n'
        '  name = "stripe-prod-key"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any("data:aws_secretsmanager_secret:stripe" in s.name for s in result.secret_hints)


# ---------- IAM wildcards ----------


def test_iam_policy_with_wildcard_action_emits_low_confidence_auth(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "broad" {\n'
        '  name = "broad-policy"\n'
        '  role = aws_iam_role.app.id\n'
        '  policy = jsonencode({\n'
        '    Version = "2012-10-17"\n'
        '    Statement = [{\n'
        '      Effect = "Allow"\n'
        '      Action = "*"\n'
        '      Resource = "*"\n'
        '    }]\n'
        '  })\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    by_hint = {h.hint: h for h in result.auth_hints}
    assert "iam_wildcard_action:broad" in by_hint
    assert by_hint["iam_wildcard_action:broad"].confidence == 0.7


def test_iam_policy_without_wildcard_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role_policy" "narrow" {\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Action = ["s3:GetObject"]\n'
        '    }]\n'
        '  })\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert not any("iam_wildcard_action" in h.hint for h in result.auth_hints)


# ---------- Cognito ----------


def test_cognito_user_pool_emits_auth_hint(tmp_path: Path) -> None:
    (tmp_path / "auth.tf").write_text(
        'resource "aws_cognito_user_pool" "users" {\n'
        '  name = "demo-users"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(h.hint == "cognito_user_pool:users" for h in result.auth_hints)


# ---------- Modules ----------


def test_modules_emit_service_hints(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'module "vpc" {\n'
        '  source = "./modules/vpc"\n'
        '}\n'
        '\n'
        'module "rds" {\n'
        '  source = "./modules/rds"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    hints = {h.hint for h in result.service_hints}
    assert "module:vpc" in hints
    assert "module:rds" in hints


# ---------- Nested-block depth handling ----------


def test_nested_blocks_do_not_break_extraction(tmp_path: Path) -> None:
    """An aws_security_group with TWO ingress blocks must still extract correctly."""
    (tmp_path / "sg.tf").write_text(
        'resource "aws_security_group" "multi" {\n'
        '  name = "multi-sg"\n'
        '  ingress {\n'
        '    cidr_blocks = ["10.0.0.0/8"]\n'
        '    from_port = 22\n'
        '    to_port = 22\n'
        '    protocol = "tcp"\n'
        '  }\n'
        '  ingress {\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '    from_port = 443\n'
        '    to_port = 443\n'
        '    protocol = "tcp"\n'
        '  }\n'
        '}\n'
        '\n'
        'resource "aws_db_instance" "after" {\n'
        '  engine = "mysql"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    # The SG body contains 0.0.0.0/0 in the second ingress block — should fire.
    assert any(e.hint == "sg_open_ingress:multi" for e in result.entrypoint_hints)
    # And the next resource (mysql DB) must still parse correctly — i.e. the brace
    # walker correctly closed the SG block.
    assert any(d.kind == "mysql" for d in result.databases)


# ---------- Azure / GCP ----------


def test_azure_open_nsg(tmp_path: Path) -> None:
    (tmp_path / "azure.tf").write_text(
        'resource "azurerm_network_security_rule" "open" {\n'
        '  name                       = "AllowAll"\n'
        '  source_address_prefixes     = ["0.0.0.0/0"]\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(e.hint == "azure_nsg_open:open" for e in result.entrypoint_hints)


def test_gcp_open_firewall(tmp_path: Path) -> None:
    (tmp_path / "gcp.tf").write_text(
        'resource "google_compute_firewall" "any" {\n'
        '  source_ranges = ["0.0.0.0/0"]\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(e.hint == "gcp_firewall_open:any" for e in result.entrypoint_hints)


def test_gcp_sql_postgres_database_kind(tmp_path: Path) -> None:
    (tmp_path / "gcp.tf").write_text(
        'resource "google_sql_database_instance" "main" {\n'
        '  database_version = "POSTGRES_14"\n'
        '}\n',
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert any(d.kind == "postgresql" for d in result.databases)


# ---------- End-to-end ----------


def test_full_aws_payment_stack_signal_set(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'provider "aws" {\n'
        '  region = "us-east-1"\n'
        '}\n'
        '\n'
        'variable "stripe_secret" {\n'
        '  sensitive = true\n'
        '}\n'
        '\n'
        'resource "aws_secretsmanager_secret" "jwt" {\n'
        '  name = "jwt-secret"\n'
        '}\n'
        '\n'
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '    from_port = 443\n'
        '    to_port = 443\n'
        '  }\n'
        '}\n'
        '\n'
        'resource "aws_db_instance" "billing" {\n'
        '  engine              = "postgres"\n'
        '  publicly_accessible = false\n'
        '}\n'
        '\n'
        'resource "aws_apigatewayv2_route" "charge" {\n'
        '  route_key          = "POST /charges"\n'
        '  authorization_type = "NONE"\n'
        '}\n'
        '\n'
        'resource "aws_iam_role_policy" "broad" {\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = "*", Resource = "*"}]})\n'
        '}\n',
        encoding="utf-8",
    )

    result = TerraformAnalyzer().analyze(tmp_path)

    assert any(f.hint == "terraform-aws" for f in result.framework_hints)

    secret_names = {s.name for s in result.secret_hints}
    assert "stripe_secret" in secret_names
    assert "secretsmanager:jwt" in secret_names

    eps = {e.hint for e in result.entrypoint_hints}
    assert "sg_open_ingress:web" in eps
    assert "apigwv2_open:charge" in eps

    assert any(d.kind == "postgresql" for d in result.databases)
    assert any((r.path, r.method) == ("/charges", "POST") for r in result.routes)
    assert any(h.hint == "iam_wildcard_action:broad" for h in result.auth_hints)


# ---------- Repo walking (AttackMap#253) ----------

_WALK_FIXTURE = (
    'provider "aws" {\n'
    '  region = "us-east-1"\n'
    '}\n'
    '\n'
    'resource "aws_secretsmanager_secret" "stripe" {\n'
    '  name = "stripe-secret-key"\n'
    '}\n'
)


@pytest.mark.parametrize("parents", [("build", "out"), ("vendor", ".terraform")])
def test_repo_under_skip_dir_named_parents_is_analyzed(tmp_path: Path, parents: tuple[str, ...]) -> None:
    """A checkout under /.../build/out/... must not be skipped (absolute-path bug)."""
    repo = tmp_path.joinpath(*parents) / "repo"
    (repo / "infra").mkdir(parents=True)
    (repo / "infra" / "main.tf").write_text(_WALK_FIXTURE, encoding="utf-8")
    analyzer = TerraformAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert result.files_scanned == 1
    assert any(f.hint == "terraform-aws" for f in result.framework_hints)
    assert any(s.name == "secretsmanager:stripe" and s.file == "infra/main.tf" for s in result.secret_hints)


def test_tf_json_is_still_walked(tmp_path: Path) -> None:
    (tmp_path / "main.tf.json").write_text('{"provider": {"aws": {}}}\n', encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    assert TerraformAnalyzer().detect(tmp_path) is True
    assert TerraformAnalyzer().analyze(tmp_path).files_scanned == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_file_outside_repo_not_analyzed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secrets.tf").write_text(_WALK_FIXTURE, encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text('variable "region" {}\n', encoding="utf-8")
    (repo / "secrets.tf").symlink_to(outside / "secrets.tf")
    result = TerraformAnalyzer().analyze(repo)
    assert result.files_scanned == 1
    assert result.secret_hints == []
    assert result.framework_hints == []


# ---------- #3: misreads (egress, IAM documents, S3, tfvars, .tf.json) ----------


_ISSUE3_MAIN_TF = '''provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "internal" {
  name = "internal"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "assets"
  acl    = "public-read"
}
'''

_ISSUE3_RDS_TF_JSON = '''{
  "resource": {
    "aws_db_instance": {
      "main": {
        "engine": "postgres",
        "instance_class": "db.t3.micro",
        "publicly_accessible": true
      }
    }
  }
}
'''


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _signals(result) -> set[tuple[str, str]]:
    """Every emitted security-relevant signal as (category, identity)."""
    out: set[tuple[str, str]] = set()
    out |= {("entrypoint", e.hint) for e in result.entrypoint_hints}
    out |= {("auth", a.hint) for a in result.auth_hints}
    out |= {("secret", s.name) for s in result.secret_hints}
    out |= {("database", d.kind) for d in result.databases}
    out |= {("service", s.hint) for s in result.service_hints}
    out |= {("framework", f.hint) for f in result.framework_hints}
    out |= {("route", f"{r.method} {r.path}") for r in result.routes}
    return out


def test_issue3_fixture_has_no_false_positives_and_all_true_positives(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", _ISSUE3_MAIN_TF)
    _write(tmp_path / "prod.tfvars", 'region      = "us-east-1"\ndb_password = "hunter2-prod"\n')
    _write(tmp_path / "rds.tf.json", _ISSUE3_RDS_TF_JSON)
    result = TerraformAnalyzer().analyze(tmp_path)

    eps = {e.hint for e in result.entrypoint_hints}
    assert eps == {"s3_public_acl:assets", "rds_publicly_accessible:main"}
    assert "iam_wildcard_action:admin" in {a.hint for a in result.auth_hints}
    secret = next(s for s in result.secret_hints if s.name == "db_password")
    assert secret.kind == "hardcoded"
    assert secret.file == "prod.tfvars" and secret.line == 2
    assert "hunter2" not in (secret.evidence_text or "")
    assert not any(s.name == "region" for s in result.secret_hints)
    rds = next(e for e in result.entrypoint_hints if e.hint == "rds_publicly_accessible:main")
    assert (rds.file, rds.line) == ("rds.tf.json", 4)
    assert any(d.kind == "postgresql" and d.file == "rds.tf.json" for d in result.databases)


def test_security_group_with_only_open_egress_is_not_open_ingress(tmp_path: Path) -> None:
    _write(tmp_path / "sg.tf", _ISSUE3_MAIN_TF)
    result = TerraformAnalyzer().analyze(tmp_path)
    assert not any("sg_open" in e.hint for e in result.entrypoint_hints)


def test_security_group_open_ipv6_ingress_still_fires(tmp_path: Path) -> None:
    _write(
        tmp_path / "sg.tf",
        'resource "aws_security_group" "web" {\n'
        '  egress {\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '  ingress {\n'
        '    from_port        = 443\n'
        '    to_port          = 443\n'
        '    ipv6_cidr_blocks = ["::/0"]\n'
        '  }\n'
        '}\n',
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert "sg_open_ingress:web" in {e.hint for e in result.entrypoint_hints}


def test_security_group_attribute_syntax_ingress(tmp_path: Path) -> None:
    _write(
        tmp_path / "sg.tf",
        'resource "aws_security_group" "attr_open" {\n'
        '  ingress = [{\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }]\n'
        '}\n'
        'resource "aws_security_group" "attr_egress" {\n'
        '  ingress = []\n'
        '  egress = [{\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }]\n'
        '}\n',
    )
    hints = {e.hint for e in TerraformAnalyzer().analyze(tmp_path).entrypoint_hints}
    assert "sg_open_ingress:attr_open" in hints
    assert "sg_open_ingress:attr_egress" not in hints


def test_egress_rules_are_not_reported_as_open(tmp_path: Path) -> None:
    _write(
        tmp_path / "rules.tf",
        'resource "aws_security_group_rule" "out" {\n'
        '  type        = "egress"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "aws_security_group_rule" "in" {\n'
        '  type        = "ingress"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n'
        'resource "azurerm_network_security_rule" "out" {\n'
        '  direction                  = "Outbound"\n'
        '  destination_address_prefix = "0.0.0.0/0"\n'
        '}\n'
        'resource "google_compute_firewall" "out" {\n'
        '  direction          = "EGRESS"\n'
        '  destination_ranges = ["0.0.0.0/0"]\n'
        '}\n',
    )
    hints = {e.hint for e in TerraformAnalyzer().analyze(tmp_path).entrypoint_hints}
    assert hints == {"sg_rule_ingress_open:in"}


def test_extract_attr_ignores_nested_block_attributes(tmp_path: Path) -> None:
    # `type = "SecureString"` lives in a nested map, the parameter itself is a
    # plain String: no secret.
    _write(
        tmp_path / "ssm.tf",
        'resource "aws_ssm_parameter" "cfg" {\n'
        '  tags = {\n'
        '    type = "SecureString"\n'
        '  }\n'
        '  name  = "/app/config"\n'
        '  type  = "String"\n'
        '  value = "x"\n'
        '}\n',
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert not any(s.name == "ssm:cfg" for s in result.secret_hints)


def test_extract_attr_nested_type_does_not_mislabel_rule_direction(tmp_path: Path) -> None:
    _write(
        tmp_path / "rule.tf",
        'resource "aws_security_group_rule" "in" {\n'
        '  timeouts {\n'
        '    type = "egress"\n'
        '  }\n'
        '  type        = "ingress"\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        '}\n',
    )
    hints = {e.hint for e in TerraformAnalyzer().analyze(tmp_path).entrypoint_hints}
    assert hints == {"sg_rule_ingress_open:in"}


def test_policy_document_wildcards(tmp_path: Path) -> None:
    _write(
        tmp_path / "iam.tf",
        'data "aws_iam_policy_document" "admin" {\n'
        '  statement {\n'
        '    actions   = ["*"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n'
        'data "aws_iam_policy_document" "describe" {\n'
        '  statement {\n'
        '    actions   = ["ec2:Describe*", "s3:*"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n'
        'data "aws_iam_policy_document" "scoped" {\n'
        '  statement {\n'
        '    actions   = ["s3:GetObject"]\n'
        '    resources = ["arn:aws:s3:::bucket/*"]\n'
        '  }\n'
        '}\n'
        'data "aws_iam_policy_document" "deny_all" {\n'
        '  statement {\n'
        '    effect    = "Deny"\n'
        '    actions   = ["*"]\n'
        '    resources = ["*"]\n'
        '  }\n'
        '}\n',
    )
    by_hint = {a.hint: a for a in TerraformAnalyzer().analyze(tmp_path).auth_hints}
    assert by_hint["iam_wildcard_action:admin"].confidence == 0.7
    assert by_hint["iam_wildcard_resource:admin"].confidence == 0.5
    assert by_hint["iam_wildcard_action:admin"].line == 1
    assert "iam_wildcard_resource:describe" in by_hint
    assert "iam_wildcard_action:describe" not in by_hint
    assert not any(h.endswith((":scoped", ":deny_all")) for h in by_hint)


def test_policy_document_wildcard_principal(tmp_path: Path) -> None:
    _write(
        tmp_path / "trust.tf",
        'data "aws_iam_policy_document" "anyone" {\n'
        '  statement {\n'
        '    actions = ["sts:AssumeRole"]\n'
        '    principals {\n'
        '      type        = "AWS"\n'
        '      identifiers = ["*"]\n'
        '    }\n'
        '  }\n'
        '}\n'
        'data "aws_iam_policy_document" "conditioned" {\n'
        '  statement {\n'
        '    actions = ["sts:AssumeRole"]\n'
        '    principals {\n'
        '      type        = "AWS"\n'
        '      identifiers = ["*"]\n'
        '    }\n'
        '    condition {\n'
        '      test     = "StringEquals"\n'
        '      variable = "aws:PrincipalOrgID"\n'
        '      values   = ["o-123"]\n'
        '    }\n'
        '  }\n'
        '}\n'
        'data "aws_iam_policy_document" "lambda" {\n'
        '  statement {\n'
        '    actions = ["sts:AssumeRole"]\n'
        '    principals {\n'
        '      type        = "Service"\n'
        '      identifiers = ["lambda.amazonaws.com"]\n'
        '    }\n'
        '  }\n'
        '}\n',
    )
    hints = {a.hint for a in TerraformAnalyzer().analyze(tmp_path).auth_hints}
    assert hints == {"iam_wildcard_principal:anyone"}


def test_role_trust_policy_wildcard_principal(tmp_path: Path) -> None:
    _write(
        tmp_path / "role.tf",
        'resource "aws_iam_role" "open" {\n'
        '  assume_role_policy = jsonencode({\n'
        '    Version = "2012-10-17"\n'
        '    Statement = [{\n'
        '      Effect    = "Allow"\n'
        '      Action    = "sts:AssumeRole"\n'
        '      Principal = { AWS = "*" }\n'
        '    }]\n'
        '  })\n'
        '}\n'
        'resource "aws_iam_role" "star" {\n'
        '  assume_role_policy = <<EOF\n'
        '{\n'
        '  "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]\n'
        '}\n'
        'EOF\n'
        '}\n'
        'resource "aws_iam_role" "lambda" {\n'
        '  assume_role_policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Effect    = "Allow"\n'
        '      Action    = "sts:AssumeRole"\n'
        '      Principal = { Service = "lambda.amazonaws.com" }\n'
        '    }]\n'
        '  })\n'
        '}\n',
    )
    hints = {a.hint for a in TerraformAnalyzer().analyze(tmp_path).auth_hints}
    assert hints == {"iam_wildcard_principal:open", "iam_wildcard_principal:star"}


def test_iam_policy_keys_are_case_insensitive_and_resource_checked(tmp_path: Path) -> None:
    _write(
        tmp_path / "iam.tf",
        'resource "aws_iam_policy" "lower" {\n'
        '  policy = <<EOF\n'
        '{"statement": [{"effect": "Allow", "action": ["*"], "resource": "arn:aws:s3:::b"}]}\n'
        'EOF\n'
        '}\n'
        'resource "aws_iam_policy" "res" {\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = "*"}]})\n'
        '}\n'
        'resource "aws_iam_policy" "denied" {\n'
        '  policy = jsonencode({Statement = [{Effect = "Deny", Action = "*", Resource = "*"}]})\n'
        '}\n',
    )
    hints = {a.hint for a in TerraformAnalyzer().analyze(tmp_path).auth_hints}
    assert hints == {"iam_wildcard_action:lower", "iam_wildcard_resource:res"}


def test_s3_inline_acl_and_bucket_policy(tmp_path: Path) -> None:
    _write(
        tmp_path / "s3.tf",
        'resource "aws_s3_bucket" "private" {\n'
        '  bucket = "private"\n'
        '  acl    = "private"\n'
        '}\n'
        'resource "aws_s3_bucket" "inline_policy" {\n'
        '  bucket = "site"\n'
        '  policy = <<EOF\n'
        '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::site/*"}]}\n'
        'EOF\n'
        '}\n'
        'resource "aws_s3_bucket_policy" "public" {\n'
        '  bucket = aws_s3_bucket.private.id\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = ["*"] }\n'
        '      Action    = "s3:GetObject"\n'
        '      Resource  = "arn:aws:s3:::private/*"\n'
        '    }]\n'
        '  })\n'
        '}\n'
        'resource "aws_s3_bucket_policy" "tls_only" {\n'
        '  bucket = aws_s3_bucket.private.id\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Effect    = "Deny"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:*"\n'
        '      Resource  = "arn:aws:s3:::private/*"\n'
        '      Condition = { Bool = { "aws:SecureTransport" = "false" } }\n'
        '    }]\n'
        '  })\n'
        '}\n',
    )
    hints = {e.hint for e in TerraformAnalyzer().analyze(tmp_path).entrypoint_hints}
    assert hints == {"s3_public_policy:inline_policy", "s3_public_policy:public"}


def test_tfvars_hardcoded_secrets(tmp_path: Path) -> None:
    _write(
        tmp_path / "terraform.tfvars",
        '# comment\n'
        'region          = "us-east-1"\n'
        'api_token       = "tok_live_abc"\n'
        'kms_key_id      = "1234abcd-12ab"\n'
        'ssh_key_name    = "deployer"\n'
        'db_password     = ""\n'
        'secret_arn      = "arn:aws:secretsmanager:us-east-1:1:secret:x"\n'
        'tags = {\n'
        '  password = "not-top-level"\n'
        '}\n',
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    secrets = {s.name: s for s in result.secret_hints}
    assert set(secrets) == {"api_token"}
    assert secrets["api_token"].kind == "hardcoded"
    assert secrets["api_token"].line == 3
    assert "tok_live" not in (secrets["api_token"].evidence_text or "")


_PARITY_HCL = '''provider "aws" {
  region = "us-east-1"
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_security_group" "internal" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_s3_bucket" "assets" {
  acl = "public-read"
}

resource "aws_iam_role" "open" {
  assume_role_policy = <<EOT
{"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}]}
EOT
}

resource "aws_apigatewayv2_route" "create" {
  route_key          = "POST /users"
  authorization_type = "NONE"
}

resource "aws_ssm_parameter" "cfg" {
  type = "String"
  tags = {
    type = "SecureString"
  }
}

data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

module "vpc" {
  source = "./vpc"
}
'''

_PARITY_JSON = '''{
  "provider": {"aws": {"region": "us-east-1"}},
  "variable": {"db_password": {"type": "string", "sensitive": true}},
  "resource": {
    "aws_security_group": {
      "internal": {
        "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}],
        "egress": [{"cidr_blocks": ["0.0.0.0/0"]}]
      },
      "web": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}
    },
    "aws_db_instance": {"main": {"engine": "postgres", "publicly_accessible": true}},
    "aws_s3_bucket": {"assets": {"acl": "public-read"}},
    "aws_iam_role": {
      "open": {
        "assume_role_policy": "{\\"Statement\\": [{\\"Effect\\": \\"Allow\\", \\"Action\\": \\"sts:AssumeRole\\", \\"Principal\\": {\\"AWS\\": \\"*\\"}}]}"
      }
    },
    "aws_apigatewayv2_route": {"create": {"route_key": "POST /users", "authorization_type": "NONE"}},
    "aws_ssm_parameter": {"cfg": {"type": "String", "tags": {"type": "SecureString"}}}
  },
  "data": {
    "aws_iam_policy_document": {
      "admin": {"statement": [{"actions": ["*"], "resources": ["*"]}]}
    }
  },
  "module": {"vpc": {"source": "./vpc"}}
}
'''


def test_tf_json_resources_are_analyzed_identically_to_hcl(tmp_path: Path) -> None:
    hcl_repo = tmp_path / "hcl"
    json_repo = tmp_path / "json"
    hcl_repo.mkdir()
    json_repo.mkdir()
    _write(hcl_repo / "main.tf", _PARITY_HCL)
    _write(json_repo / "main.tf.json", _PARITY_JSON)

    hcl = TerraformAnalyzer().analyze(hcl_repo)
    from_json = TerraformAnalyzer().analyze(json_repo)

    expected = {
        ("framework", "terraform-aws"),
        ("secret", "db_password"),
        ("entrypoint", "sg_open_ingress:web"),
        ("entrypoint", "rds_publicly_accessible:main"),
        ("entrypoint", "s3_public_acl:assets"),
        ("entrypoint", "apigwv2_open:create"),
        ("auth", "iam_wildcard_principal:open"),
        ("auth", "iam_wildcard_action:admin"),
        ("auth", "iam_wildcard_resource:admin"),
        ("database", "postgresql"),
        ("service", "rds:main"),
        ("service", "s3_bucket:assets"),
        ("service", "module:vpc"),
        ("route", "POST /users"),
    }
    assert _signals(hcl) == expected
    assert _signals(from_json) == expected


def test_tf_json_lines_point_at_the_json_source(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf.json", _PARITY_JSON)
    result = TerraformAnalyzer().analyze(tmp_path)
    web = next(e for e in result.entrypoint_hints if e.hint == "sg_open_ingress:web")
    assert web.file == "main.tf.json"
    assert web.line == _PARITY_JSON.splitlines().index(
        next(line for line in _PARITY_JSON.splitlines() if '"web"' in line)
    ) + 1
    assert '"web"' in (web.evidence_text or "")


def test_tf_json_invalid_json_is_skipped(tmp_path: Path) -> None:
    _write(tmp_path / "broken.tf.json", '{"resource": ')
    result = TerraformAnalyzer().analyze(tmp_path)
    assert result.files_scanned == 1
    assert _signals(result) == set()


# ---------- Route.auth contract (AttackMap#256) ----------

_REST_API = (
    'resource "aws_api_gateway_rest_api" "api" {\n'
    '  name = "orders"\n'
    "}\n\n"
    'resource "aws_api_gateway_resource" "orders" {\n'
    "  rest_api_id = aws_api_gateway_rest_api.api.id\n"
    "  parent_id   = aws_api_gateway_rest_api.api.root_resource_id\n"
    '  path_part   = "orders"\n'
    "}\n\n"
    'resource "aws_api_gateway_resource" "order" {\n'
    "  rest_api_id = aws_api_gateway_rest_api.api.id\n"
    "  parent_id   = aws_api_gateway_resource.orders.id\n"
    '  path_part   = "{id}"\n'
    "}\n"
)
_REST_METHODS = (
    'resource "aws_api_gateway_method" "create_order" {\n'
    "  rest_api_id   = aws_api_gateway_rest_api.api.id\n"
    "  resource_id   = aws_api_gateway_resource.orders.id\n"
    '  http_method   = "POST"\n'
    '  authorization = "COGNITO_USER_POOLS"\n'
    "  authorizer_id = aws_api_gateway_authorizer.cognito.id\n"
    "}\n\n"
    'resource "aws_api_gateway_method" "cancel_order" {\n'
    "  rest_api_id   = aws_api_gateway_rest_api.api.id\n"
    "  resource_id   = aws_api_gateway_resource.order.id\n"
    '  http_method   = "DELETE"\n'
    '  authorization = "NONE"\n'
    "}\n\n"
    'resource "aws_api_gateway_method" "update_order" {\n'
    "  rest_api_id      = aws_api_gateway_rest_api.api.id\n"
    "  resource_id      = aws_api_gateway_resource.order.id\n"
    '  http_method      = "PUT"\n'
    '  authorization    = "NONE"\n'
    "  api_key_required = true\n"
    "}\n"
)


def _routes_by_key(result) -> dict:
    return {f"{r.method} {r.path}": r for r in result.routes}


def test_rest_api_methods_become_routes_with_declared_auth(tmp_path: Path) -> None:
    # Resources and methods in different files: paths resolve after the walk.
    (tmp_path / "api.tf").write_text(_REST_API, encoding="utf-8")
    (tmp_path / "methods.tf").write_text(_REST_METHODS, encoding="utf-8")
    routes = _routes_by_key(TerraformAnalyzer().analyze(tmp_path))
    create = routes["POST /orders"]
    assert create.auth == "required"
    assert create.guards == ["COGNITO_USER_POOLS (aws_api_gateway_authorizer.cognito.id)"]
    assert create.guard_evidence == (
        'authorization = "COGNITO_USER_POOLS"; authorizer_id = aws_api_gateway_authorizer.cognito.id'
    )
    assert create.file == "methods.tf" and create.line == 1


def test_rest_api_method_with_authorization_none_is_anonymous(tmp_path: Path) -> None:
    (tmp_path / "api.tf").write_text(_REST_API + "\n" + _REST_METHODS, encoding="utf-8")
    routes = _routes_by_key(TerraformAnalyzer().analyze(tmp_path))
    # A NONE method nested under the guarded /orders resource: API Gateway
    # authorizes per method, so the parent's authorizer doesn't carry over.
    cancel = routes["DELETE /orders/{id}"]
    assert cancel.auth == "anonymous"
    assert cancel.guards == []
    assert cancel.guard_evidence == 'authorization = "NONE"'
    # NONE plus a required API key still rejects callers without the key.
    update = routes["PUT /orders/{id}"]
    assert update.auth == "required"
    assert update.guards == ["api_key_required"]


def test_http_api_route_authorization_type(tmp_path: Path) -> None:
    (tmp_path / "http.tf").write_text(
        'resource "aws_apigatewayv2_route" "create_user" {\n'
        "  api_id             = aws_apigatewayv2_api.api.id\n"
        '  route_key          = "POST /users"\n'
        '  authorization_type = "JWT"\n'
        "  authorizer_id      = aws_apigatewayv2_authorizer.jwt.id\n"
        "}\n\n"
        'resource "aws_apigatewayv2_route" "signup" {\n'
        "  api_id             = aws_apigatewayv2_api.api.id\n"
        '  route_key          = "POST /signup"\n'
        '  authorization_type = "NONE"\n'
        "}\n\n"
        'resource "aws_apigatewayv2_route" "computed" {\n'
        "  api_id             = aws_apigatewayv2_api.api.id\n"
        '  route_key          = "PUT /settings"\n'
        "  authorization_type = var.settings_auth\n"
        "}\n\n"
        'resource "aws_apigatewayv2_route" "implicit" {\n'
        "  api_id    = aws_apigatewayv2_api.api.id\n"
        '  route_key = "DELETE /cache"\n'
        "}\n",
        encoding="utf-8",
    )
    routes = _routes_by_key(TerraformAnalyzer().analyze(tmp_path))
    assert routes["POST /users"].auth == "required"
    assert routes["POST /users"].guards == ["JWT (aws_apigatewayv2_authorizer.jwt.id)"]
    assert routes["POST /signup"].auth == "anonymous"
    assert routes["POST /signup"].guard_evidence == 'authorization_type = "NONE"'
    # Computed or omitted: not declared either way.
    assert routes["PUT /settings"].auth == "unknown"
    assert routes["DELETE /cache"].auth == "unknown"
    assert routes["DELETE /cache"].guard_evidence is None


def test_lambda_function_url_is_a_route_with_its_auth(tmp_path: Path) -> None:
    (tmp_path / "lambda.tf").write_text(
        'resource "aws_lambda_function_url" "open" {\n'
        "  function_name      = aws_lambda_function.fn.function_name\n"
        '  authorization_type = "NONE"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "iam.tf").write_text(
        'resource "aws_lambda_function_url" "iam" {\n'
        "  function_name      = aws_lambda_function.fn.function_name\n"
        '  authorization_type = "AWS_IAM"\n'
        "}\n",
        encoding="utf-8",
    )
    routes = {(r.file, r.method, r.path): r for r in TerraformAnalyzer().analyze(tmp_path).routes}
    assert routes[("lambda.tf", "ANY", "/")].auth == "anonymous"
    assert routes[("iam.tf", "ANY", "/")].auth == "required"
    assert routes[("iam.tf", "ANY", "/")].guards == ["AWS_IAM"]


def test_rest_api_method_on_unresolvable_resource_is_not_a_route(tmp_path: Path) -> None:
    (tmp_path / "m.tf").write_text(
        'resource "aws_api_gateway_method" "m" {\n'
        "  resource_id   = module.api.resource_id\n"
        '  http_method   = "POST"\n'
        '  authorization = "NONE"\n'
        "}\n",
        encoding="utf-8",
    )
    result = TerraformAnalyzer().analyze(tmp_path)
    assert result.routes == []
    assert "apigw_open_method:POST:m" in {e.hint for e in result.entrypoint_hints}
