"""Tests for the TerraformAnalyzer plugin."""

from __future__ import annotations

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
