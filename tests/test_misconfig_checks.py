"""CloudMisconfig records (#4): module pinning, for_each/count and module
context, the new public-exposure resources, kubernetes provider resources and
secret variable defaults. Every check has a positive and a negative case.

Needs AttackMap core with ``attackmap.sdk.CloudMisconfig`` (AttackMap#334).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from attackmap_analyzer_terraform import TerraformAnalyzer


def _scan(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return TerraformAnalyzer().analyze(tmp_path)


def _records(tmp_path: Path, text: str, kind: str | None = None, name: str = "main.tf"):
    result = _scan(tmp_path, {name: text})
    return [m for m in result.cloud_misconfigs if kind is None or m.kind == kind]


def _module(source: str, extra: str = "") -> str:
    return f'module "m" {{\n  source = "{source}"\n{extra}}}\n'


# ---------- Module sources ----------


@pytest.mark.parametrize(
    "source, extra, severity",
    [
        ("git::https://github.com/org/vpc.git", "", "medium"),
        ("git::https://github.com/org/vpc.git?ref=main", "", "medium"),
        ("git::ssh://git@github.com/org/vpc.git//modules/a?ref=develop", "", "medium"),
        ("github.com/org/terraform-vpc", "", "medium"),
        ("git@github.com:org/vpc.git", "", "medium"),
        ("terraform-aws-modules/vpc/aws", "", "medium"),
        ("app.terraform.io/acme/vpc/aws", '  version = ""\n', "medium"),
        ("git::https://example.com/vpc.git?ref=feature-x", "", "low"),
    ],
)
def test_unpinned_module_sources_are_flagged(tmp_path: Path, source: str, extra: str, severity: str) -> None:
    (record,) = _records(tmp_path, _module(source, extra), "iac_module_unpinned")
    assert record.resource == "module.m" and record.platform == "terraform"
    assert record.severity == severity and record.line == 2
    assert source in (record.evidence_text or "")


@pytest.mark.parametrize(
    "source, extra",
    [
        ("git::https://github.com/org/vpc.git?ref=v1.2.3", ""),
        ("git::https://github.com/org/vpc.git//sub?ref=2024.01.5", ""),
        ("git::https://github.com/org/vpc.git?ref=8f4b7f84864484a7bf31766abe9204da3cbe65b3", ""),
        ("github.com/org/vpc?ref=a1b2c3d", ""),
        ("terraform-aws-modules/vpc/aws", '  version = "5.1.2"\n'),
        ("terraform-aws-modules/vpc/aws", '  version = "~> 5.0"\n'),
        ("./modules/vpc", ""),
        ("../shared/vpc", ""),
        ("s3::https://s3.amazonaws.com/bucket/vpc.zip", ""),
        ("https://example.com/vpc-module.zip", ""),
    ],
)
def test_pinned_and_local_modules_are_not_flagged(tmp_path: Path, source: str, extra: str) -> None:
    assert _records(tmp_path, _module(source, extra), "iac_module_unpinned") == []


def test_module_keeps_its_service_hint_and_notes_for_each(tmp_path: Path) -> None:
    result = _scan(tmp_path, {"main.tf": _module("terraform-aws-modules/vpc/aws", "  for_each = toset(var.envs)\n")})
    assert "module:m" in {s.hint for s in result.service_hints}
    (record,) = result.cloud_misconfigs
    assert record.context == "for_each = toset(var.envs)"


def test_local_module_resources_are_attributed_to_the_calling_module(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        {
            "main.tf": 'module "edge" {\n  source = "./modules/edge"\n}\nmodule "out" {\n  source = "../../elsewhere"\n}\n',
            "modules/edge/main.tf": 'resource "aws_instance" "bastion" {\n  associate_public_ip_address = true\n}\n',
            "other/main.tf": 'resource "aws_instance" "solo" {\n  associate_public_ip_address = true\n}\n',
        },
    )
    by_resource = {m.resource: m for m in result.cloud_misconfigs}
    assert by_resource["aws_instance.bastion"].context == "in local module called as module.edge (main.tf:1)"
    assert by_resource["aws_instance.solo"].context is None


def test_for_each_and_count_are_noted_on_records_and_hint_evidence(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        {
            "main.tf": (
                'resource "aws_security_group" "web" {\n'
                "  for_each = { a = 1, b = 2 }\n"
                '  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
                "}\n"
                'resource "aws_instance" "i" {\n'
                "  count = var.n\n"
                "  associate_public_ip_address = true\n"
                "}\n"
            )
        },
    )
    hint = next(h for h in result.entrypoint_hints if h.hint == "sg_open_ingress:web")
    assert hint.evidence_text.endswith("[for_each = { a = 1, b = 2 }]")
    (record,) = result.cloud_misconfigs
    assert record.context == "count = var.n" and record.line == 9


def test_nested_block_count_is_not_the_resource_instancing(tmp_path: Path) -> None:
    text = (
        'resource "aws_instance" "i" {\n'
        "  associate_public_ip_address = true\n"
        "  ebs_block_device {\n    count = 3\n  }\n"
        "}\n"
    )
    (record,) = _records(tmp_path, text)
    assert record.context is None


# ---------- AWS exposure ----------


def test_public_ip_on_instances_and_launch_templates(tmp_path: Path) -> None:
    text = (
        'resource "aws_instance" "a" {\n  associate_public_ip_address = true\n}\n'
        'resource "aws_instance" "b" {\n  associate_public_ip_address = false\n}\n'
        'resource "aws_instance" "c" {\n  associate_public_ip_address = var.public\n}\n'
        'resource "aws_launch_template" "lt" {\n  network_interfaces {\n    associate_public_ip_address = true\n  }\n}\n'
        'resource "aws_launch_template" "private" {\n  network_interfaces {\n    associate_public_ip_address = false\n  }\n}\n'
    )
    records = _records(tmp_path, text, "public_network_access")
    assert sorted(m.resource for m in records) == ["aws_instance.a", "aws_launch_template.lt"]
    assert all(m.severity == "low" for m in records)


@pytest.mark.parametrize(
    "vpc_config, confidence",
    [
        ("subnet_ids = []", 0.6),
        ('endpoint_public_access = true\n    public_access_cidrs = ["0.0.0.0/0"]', 0.9),
        ("endpoint_public_access = true", 0.6),
    ],
)
def test_eks_public_endpoint(tmp_path: Path, vpc_config: str, confidence: float) -> None:
    text = f'resource "aws_eks_cluster" "c" {{\n  vpc_config {{\n    {vpc_config}\n  }}\n}}\n'
    (record,) = _records(tmp_path, text, "public_cluster_endpoint")
    assert record.confidence == confidence and record.severity == "medium"


@pytest.mark.parametrize(
    "vpc_config",
    [
        "endpoint_public_access = false",
        "endpoint_public_access = var.public",
        'endpoint_public_access = true\n    public_access_cidrs = ["203.0.113.0/24"]',
        "public_access_cidrs = var.cidrs",
    ],
)
def test_eks_private_or_restricted_endpoint_is_not_flagged(tmp_path: Path, vpc_config: str) -> None:
    text = f'resource "aws_eks_cluster" "c" {{\n  vpc_config {{\n    {vpc_config}\n  }}\n}}\n'
    assert _records(tmp_path, text, "public_cluster_endpoint") == []


def _listener(name: str, protocol: str, action: str, lb: str = "aws_lb.pub.arn") -> str:
    return (
        f'resource "aws_lb_listener" "{name}" {{\n  load_balancer_arn = {lb}\n  protocol = "{protocol}"\n'
        f'  default_action {{\n    type = "{action}"\n  }}\n}}\n'
    )


def test_http_listener_without_redirect(tmp_path: Path) -> None:
    text = (
        'resource "aws_lb" "pub" {\n  internal = false\n}\n'
        'resource "aws_lb" "int" {\n  internal = true\n}\n'
        + _listener("fwd", "HTTP", "forward")
        + _listener("fixed", "HTTP", "fixed-response")
        + _listener("redir", "HTTP", "redirect")
        + _listener("tls", "HTTPS", "forward")
        + _listener("inside", "HTTP", "forward", "aws_lb.int.arn")
    )
    records = {m.resource: m for m in _records(tmp_path, text, "plaintext_listener")}
    assert set(records) == {"aws_lb_listener.fwd", "aws_lb_listener.fixed"}
    assert records["aws_lb_listener.fwd"].severity == "medium"
    assert records["aws_lb_listener.fixed"].severity == "low"


def test_api_gateway_methods_and_routes_without_authorizer(tmp_path: Path) -> None:
    def method(name: str, verb: str, auth: str, extra: str = "") -> str:
        return (
            f'resource "aws_api_gateway_method" "{name}" {{\n  http_method = "{verb}"\n'
            f'  authorization = "{auth}"\n{extra}}}\n'
        )

    def route(name: str, key: str, extra: str = "") -> str:
        return f'resource "aws_apigatewayv2_route" "{name}" {{\n  route_key = "{key}"\n{extra}}}\n'

    text = (
        method("open", "GET", "NONE")
        + method("cors", "OPTIONS", "NONE")
        + method("keyed", "POST", "NONE", "  api_key_required = true\n")
        + method("iam", "GET", "AWS_IAM")
        + route("default_none", "POST /charges")
        + route("explicit_none", "GET /status", '  authorization_type = "NONE"\n')
        + route("jwt", "GET /me", '  authorization_type = "JWT"\n')
        + route("ws", "$connect")
    )
    records = {m.resource: m for m in _records(tmp_path, text, "api_no_authorizer")}
    assert set(records) == {
        "aws_api_gateway_method.open",
        "aws_apigatewayv2_route.default_none",
        "aws_apigatewayv2_route.explicit_none",
    }
    assert "defaults to NONE" in (records["aws_apigatewayv2_route.default_none"].evidence_text or "")
    assert records["aws_apigatewayv2_route.default_none"].confidence < records["aws_apigatewayv2_route.explicit_none"].confidence


def test_rds_encryption_at_rest(tmp_path: Path) -> None:
    text = (
        'resource "aws_db_instance" "off" {\n  storage_encrypted = false\n}\n'
        'resource "aws_db_instance" "unset" {\n  engine = "mysql"\n}\n'
        'resource "aws_db_instance" "on" {\n  storage_encrypted = true\n}\n'
        'resource "aws_db_instance" "replica" {\n  replicate_source_db = aws_db_instance.on.identifier\n}\n'
        'resource "aws_db_instance" "computed" {\n  storage_encrypted = var.encrypt\n}\n'
        'resource "aws_rds_cluster" "aurora" {\n  engine = "aurora-postgresql"\n}\n'
        'resource "aws_rds_cluster" "aurora_off" {\n  storage_encrypted = false\n}\n'
    )
    records = {m.resource: m.severity for m in _records(tmp_path, text, "unencrypted_storage")}
    assert records == {
        "aws_db_instance.off": "medium",
        "aws_db_instance.unset": "low",
        "aws_rds_cluster.aurora_off": "medium",
    }


_OPEN_POLICY = (
    'jsonencode({\n    Statement = [{\n      Effect = "Allow"\n      Principal = "*"\n'
    '      Action = "es:*"\n      Resource = "*"\n    }]\n  })'
)
_CONDITIONED_POLICY = _OPEN_POLICY.replace(
    'Resource = "*"', 'Resource = "*"\n      Condition = { IpAddress = { "aws:SourceIp" = ["10.0.0.0/8"] } }'
)


def test_opensearch_open_access_policy(tmp_path: Path) -> None:
    text = (
        f'resource "aws_opensearch_domain" "public" {{\n  access_policies = {_OPEN_POLICY}\n}}\n'
        f'resource "aws_elasticsearch_domain" "vpc" {{\n  vpc_options {{\n    subnet_ids = []\n  }}\n'
        f"  access_policies = {_OPEN_POLICY}\n}}\n"
        f'resource "aws_opensearch_domain" "cond" {{\n  access_policies = {_CONDITIONED_POLICY}\n}}\n'
        f'resource "aws_opensearch_domain_policy" "p" {{\n  access_policies = {_OPEN_POLICY}\n}}\n'
    )
    records = {m.resource: m.severity for m in _records(tmp_path, text, "public_data_access")}
    assert records == {
        "aws_opensearch_domain.public": "high",
        "aws_elasticsearch_domain.vpc": "medium",
        "aws_opensearch_domain_policy.p": "medium",
    }


def test_existing_s3_rds_and_lambda_url_exposures_become_records(tmp_path: Path) -> None:
    text = (
        'resource "aws_s3_bucket_acl" "rw" {\n  acl = "public-read-write"\n}\n'
        'resource "aws_s3_bucket_acl" "private" {\n  acl = "private"\n}\n'
        'resource "aws_s3_bucket_public_access_block" "pab" {\n  block_public_policy = false\n}\n'
        'resource "aws_db_instance" "pub" {\n  publicly_accessible = true\n  storage_encrypted = true\n}\n'
        'resource "aws_lambda_function_url" "open" {\n  authorization_type = "NONE"\n}\n'
        'resource "aws_lambda_function_url" "iam" {\n  authorization_type = "AWS_IAM"\n}\n'
    )
    records = {(m.kind, m.resource): m.severity for m in _records(tmp_path, text)}
    assert records == {
        ("public_data_access", "aws_s3_bucket_acl.rw"): "high",
        ("public_data_access", "aws_s3_bucket_public_access_block.pab"): "low",
        ("public_network_access", "aws_db_instance.pub"): "medium",
        ("public_invoker", "aws_lambda_function_url.open"): "low",
    }


# ---------- GCP ----------


def test_gcp_all_users_on_cloud_run_and_buckets(tmp_path: Path) -> None:
    text = (
        'resource "google_cloud_run_service_iam_member" "public" {\n  role = "roles/run.invoker"\n  member = "allUsers"\n}\n'
        'resource "google_cloud_run_service_iam_member" "sa" {\n  role = "roles/run.invoker"\n'
        '  member = "serviceAccount:ci@p.iam.gserviceaccount.com"\n}\n'
        'resource "google_cloudfunctions2_function_iam_binding" "b" {\n  role = "roles/cloudfunctions.invoker"\n'
        '  members = ["group:ops@example.com", "allAuthenticatedUsers"]\n}\n'
        'resource "google_storage_bucket_iam_member" "read" {\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n'
        'resource "google_storage_bucket_iam_member" "write" {\n  role = "roles/storage.objectAdmin"\n  member = "allUsers"\n}\n'
        'resource "google_storage_bucket_iam_member" "team" {\n  role = "roles/storage.objectViewer"\n  member = "group:t@example.com"\n}\n'
        'resource "google_storage_bucket_access_control" "acl" {\n  role = "READER"\n  entity = "allUsers"\n}\n'
        'resource "google_storage_bucket_acl" "pre" {\n  predefined_acl = "publicRead"\n}\n'
    )
    records = {(m.kind, m.resource): m.severity for m in _records(tmp_path, text)}
    assert records == {
        ("public_invoker", "google_cloud_run_service_iam_member.public"): "low",
        ("public_invoker", "google_cloudfunctions2_function_iam_binding.b"): "low",
        ("public_data_access", "google_storage_bucket_iam_member.read"): "medium",
        ("public_data_access", "google_storage_bucket_iam_member.write"): "high",
        ("public_data_access", "google_storage_bucket_access_control.acl"): "medium",
        ("public_data_access", "google_storage_bucket_acl.pre"): "medium",
    }
    assert all(m.platform == "gcp" for m in _records(tmp_path, text))


# ---------- Azure ----------


def test_azure_public_network_access_and_public_blobs(tmp_path: Path) -> None:
    text = (
        'resource "azurerm_postgresql_flexible_server" "on" {\n  public_network_access_enabled = true\n}\n'
        'resource "azurerm_key_vault" "off" {\n  public_network_access_enabled = false\n}\n'
        'resource "azurerm_storage_account" "sa" {\n  allow_nested_items_to_be_public = true\n}\n'
        'resource "azurerm_storage_account" "locked" {\n  allow_nested_items_to_be_public = false\n}\n'
        'resource "azurerm_storage_container" "c" {\n  container_access_type = "container"\n}\n'
        'resource "azurerm_storage_container" "b" {\n  container_access_type = "blob"\n}\n'
        'resource "azurerm_storage_container" "p" {\n  container_access_type = "private"\n}\n'
    )
    records = {(m.kind, m.resource): m.severity for m in _records(tmp_path, text)}
    assert records == {
        ("public_network_access", "azurerm_postgresql_flexible_server.on"): "medium",
        ("public_data_access", "azurerm_storage_account.sa"): "medium",
        ("public_data_access", "azurerm_storage_container.c"): "high",
        ("public_data_access", "azurerm_storage_container.b"): "medium",
    }


# ---------- kubernetes provider ----------

_RISKY_DEPLOYMENT = """resource "kubernetes_deployment" "agent" {
  spec {
    template {
      spec {
        host_network = true
        host_pid     = true
        container {
          name = "agent"
          security_context {
            privileged                 = true
            allow_privilege_escalation = true
          }
        }
        volume {
          name = "sock"
          host_path {
            path = "/var/run/docker.sock"
          }
        }
        volume {
          name = "logs"
          host_path {
            path = "/var/log/app"
          }
        }
      }
    }
  }
}
"""
_HARDENED_DEPLOYMENT = """resource "kubernetes_deployment_v1" "web" {
  spec {
    template {
      spec {
        host_network = false
        container {
          name = "web"
          security_context {
            privileged                 = false
            allow_privilege_escalation = false
            run_as_non_root            = true
          }
        }
        volume {
          name = "data"
          empty_dir {}
        }
      }
    }
  }
}
"""


def test_kubernetes_provider_workloads(tmp_path: Path) -> None:
    records = _records(tmp_path, _RISKY_DEPLOYMENT + _HARDENED_DEPLOYMENT)
    got = sorted((m.kind, m.severity, m.line) for m in records)
    assert got == [
        ("host_namespace_shared", "high", 6),
        ("host_namespace_shared", "medium", 5),
        ("host_path_mount", "high", 17),
        ("host_path_mount", "low", 23),
        ("privilege_escalation_allowed", "medium", 11),
        ("privileged_container", "high", 10),
    ]
    assert {m.resource for m in records} == {"kubernetes_deployment.agent"}
    assert all(m.platform == "kubernetes" for m in records)


def test_kubernetes_provider_rbac_and_services(tmp_path: Path) -> None:
    text = (
        'resource "kubernetes_cluster_role_binding" "ci" {\n  role_ref {\n    kind = "ClusterRole"\n'
        '    name = "cluster-admin"\n  }\n  subject {\n    kind = "ServiceAccount"\n    name = "default"\n  }\n}\n'
        'resource "kubernetes_role_binding" "reader" {\n  role_ref {\n    name = "pod-reader"\n  }\n'
        '  subject {\n    kind = "User"\n    name = "jane"\n  }\n}\n'
        'resource "kubernetes_cluster_role" "god" {\n  rule {\n    api_groups = [""]\n'
        '    resources = ["*"]\n    verbs = ["get"]\n  }\n'
        '  rule {\n    api_groups = ["rbac.authorization.k8s.io"]\n    resources = ["clusterroles"]\n'
        '    verbs = ["escalate", "bind"]\n  }\n'
        '  rule {\n    resources = ["secrets"]\n    verbs = ["list"]\n  }\n}\n'
        'resource "kubernetes_role" "ok" {\n  rule {\n    resources = ["configmaps"]\n    verbs = ["get"]\n  }\n}\n'
        'resource "kubernetes_service" "lb" {\n  spec {\n    type = "LoadBalancer"\n  }\n}\n'
        'resource "kubernetes_service_v1" "ranged" {\n  spec {\n    type = "LoadBalancer"\n'
        '    load_balancer_source_ranges = ["203.0.113.0/24"]\n  }\n}\n'
        'resource "kubernetes_service" "internal" {\n  metadata {\n    annotations = {\n'
        '      "service.beta.kubernetes.io/aws-load-balancer-internal" = "true"\n    }\n  }\n'
        '  spec {\n    type = "LoadBalancer"\n  }\n}\n'
        'resource "kubernetes_service" "cluster" {\n  spec {\n    type = "ClusterIP"\n  }\n}\n'
    )
    records = sorted((m.kind, m.resource) for m in _records(tmp_path, text))
    assert records == [
        ("cluster_admin_binding", "kubernetes_cluster_role_binding.ci"),
        ("exposed_service", "kubernetes_service.lb"),
        ("rbac_escalation", "kubernetes_cluster_role.god"),
        ("rbac_secret_access", "kubernetes_cluster_role.god"),
        ("rbac_wildcard", "kubernetes_cluster_role.god"),
    ]


# ---------- Variables ----------


def test_secret_variable_with_literal_default_is_hardcoded(tmp_path: Path) -> None:
    text = (
        'variable "db_password" {\n  type = string\n  default = "hunter2"\n}\n'
        'variable "api" {\n  sensitive = true\n  default = "sk-live-123"\n}\n'
        'variable "admin_token" {\n  type = string\n}\n'
        'variable "empty_secret" {\n  default = ""\n}\n'
        'variable "kms_key_id" {\n  default = "alias/app"\n}\n'
        'variable "region" {\n  default = "us-east-1"\n}\n'
    )
    result = _scan(tmp_path, {"variables.tf": text})
    kinds = {s.name: s.kind for s in result.secret_hints}
    assert kinds == {
        "db_password": "hardcoded",
        "api": "hardcoded",
        "admin_token": "env_reference",
        "empty_secret": "env_reference",
        "kms_key_id": "env_reference",
    }
    rendered = json.dumps([s.model_dump() for s in result.secret_hints])
    assert "hunter2" not in rendered and "sk-live-123" not in rendered


# ---------- .tf.json ----------


def test_tf_json_modules_and_resources(tmp_path: Path) -> None:
    document = {
        "module": {"vpc": {"source": "git::https://github.com/org/vpc.git"}},
        "resource": {"aws_db_instance": {"db": {"storage_encrypted": False, "count": 2}}},
    }
    result = _scan(tmp_path, {"main.tf.json": json.dumps(document, indent=2)})
    records = {m.kind: m for m in result.cloud_misconfigs}
    assert set(records) == {"iac_module_unpinned", "unencrypted_storage"}
    assert records["unencrypted_storage"].context == "count = 2"
    assert "module:vpc" in {s.hint for s in result.service_hints}


# ---------- Robustness ----------


_FRAGMENTS = [
    'resource "aws_eks_cluster" "c" {', "vpc_config {", 'module "m" {', 'source = "git::x.git?ref=',
    "host_path {", 'path = "/"', "}", "{", '"', "for_each = {", "count = ", "rule {", 'verbs = ["*"',
    'resource "kubernetes_pod" "p" {', 'protocol = "HTTP"', "default_action {", "\n", "<<EOT\n", "EOT\n",
    'variable "secret" {', 'default = "x', "\\", "${", 'resource "aws_lb_listener" "l" {',
]


@pytest.mark.parametrize("seed", range(40))
def test_random_and_truncated_hcl_never_raises(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    text = " ".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(1, 80)))
    (tmp_path / "fuzz.tf").write_text(text[: rng.randint(0, len(text))], encoding="utf-8")
    (tmp_path / "fuzz.tf.json").write_text('{"module": {"m": [1, {"source": 3}]}, "resource": {"x": 1}}', encoding="utf-8")
    TerraformAnalyzer().analyze(tmp_path)


def test_records_become_core_findings(tmp_path: Path) -> None:
    from attackmap.analyzers import analyze_repository
    from attackmap.recon_to_analysis import translate_recon

    (tmp_path / "main.tf").write_text(
        _module("git::https://github.com/org/vpc.git?ref=main")
        + 'resource "aws_db_instance" "db" {\n  storage_encrypted = false\n}\n',
        encoding="utf-8",
    )
    scan = analyze_repository(tmp_path, analyzers=[TerraformAnalyzer()])
    rule_ids = {f.rule_id for f in translate_recon(scan).findings}
    assert {"iac-module-unpinned", "unencrypted-storage"} <= rule_ids


# ---------- Review round 1 ----------

import subprocess
import sys
import time

_RUN = "import sys; from attackmap_analyzer_terraform import TerraformAnalyzer; TerraformAnalyzer().analyze(sys.argv[1])"


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode(' + "{" * 100000 + ")\n}\n",
        'resource "aws_instance" "x" {\n' * 30000,
        "".join(f'module "m{i}" {{\n  source = "./m"\n}}\n' for i in range(40000)),
        "".join(f'resource "aws_instance" "i{i}" {{\n  associate_public_ip_address = true\n}}\n' for i in range(20000)),
        'resource "kubernetes_pod" "p" {\n' + "  a {\n" * 50000,
        # Round 3: heredoc mode mismatch between depth scan and body scan.
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode(' + "{ <<EOF\n}\nEOF\n" * 8000 + ")\n}\n",
    ],
    ids=["nested-policy", "unterminated-resources", "many-modules", "many-records", "nested-blocks",
         "heredocs-in-policy"],
)
def test_hostile_input_is_fast(tmp_path: Path, text: str) -> None:
    import os

    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    start = time.monotonic()
    proc = subprocess.run([sys.executable, "-c", _RUN, str(tmp_path)], env=env, timeout=60, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert time.monotonic() - start < 20  # each took 18 s to >90 s before


def test_policy_statements_are_still_found_at_normal_depth(tmp_path: Path) -> None:
    text = (
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Statement = [{\n'
        '      Effect = "Allow"\n      Action = "*"\n      Resource = "*"\n    }]\n  })\n}\n'
    )
    hints = {h.hint for h in _scan(tmp_path, {"main.tf": text}).auth_hints}
    assert {"iam_wildcard_action:p", "iam_wildcard_resource:p"} <= hints


def test_repeated_signals_are_deduplicated(tmp_path: Path) -> None:
    text = 'module "m" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n' * 3
    result = _scan(tmp_path, {"main.tf": text})
    assert [s.hint for s in result.service_hints] == ["module:m"]


def test_duplicate_records_are_deduplicated(tmp_path: Path) -> None:
    text = 'resource "aws_instance" "a" {\n  associate_public_ip_address = true\n}\n'
    result = _scan(tmp_path, {"a.tf": text, "b.tf": text.replace('"a"', '"b"')})
    assert len(result.cloud_misconfigs) == 2
    again = TerraformAnalyzer()
    first = again.analyze(tmp_path)
    assert len(first.cloud_misconfigs) == 2  # per-result keys don't leak between runs


def test_indexed_lb_refs_per_module_dir_and_dynamic_redirects(tmp_path: Path) -> None:
    lb = 'resource "aws_lb" "this" {\n  count = 1\n  internal = %s\n}\n'
    listener = (
        'resource "aws_lb_listener" "%s" {\n  load_balancer_arn = aws_lb.this[0].arn\n  protocol = "HTTP"\n%s}\n'
    )
    forward = '  default_action {\n    type = "forward"\n  }\n'
    dyn_redirect = '  dynamic "default_action" {\n    for_each = [1]\n    content {\n      type = "redirect"\n    }\n  }\n'
    dyn_forward = dyn_redirect.replace("redirect", "forward")
    computed = '  default_action {\n    type = var.action\n  }\n'
    result = _scan(
        tmp_path,
        {
            "internal/main.tf": lb % "true" + listener % ("a", forward),
            "public/main.tf": lb % "false" + listener % ("b", forward) + listener % ("c", dyn_redirect)
            + listener % ("d", computed) + listener % ("g", dyn_forward),
            "computed/main.tf": lb % "var.internal" + listener % ("e", forward),
            "unresolved/main.tf": listener.replace("aws_lb.this[0].arn", "var.lb_arn") % ("f", forward),
        },
    )
    records = {m.resource: m.confidence for m in result.cloud_misconfigs if m.kind == "plaintext_listener"}
    assert records == {"aws_lb_listener.b": 0.8, "aws_lb_listener.g": 0.8, "aws_lb_listener.f": 0.6}


@pytest.mark.parametrize(
    "name, value, hardcoded",
    [
        ("db_password", "hunter2!x", True),
        ("api_token", "sk-live-1234567", True),
        ("ssh_public_key", "ssh-rsa AAAAB3NzaC1yc2E user@host", False),
        ("db_password", "postgres://app:s3cretpw@db:5432/app", True),
        ("token_url", "https://auth.example.com/token", False),
        ("secret_key_id", "UserId", False),
        ("password_mode", "off", False),
        ("master_password", "master", False),
        ("admin_username", "administrator1", False),
        ("db_password", "abc12", False),
    ],
)
def test_secret_default_value_shape(tmp_path: Path, name: str, value: str, hardcoded: bool) -> None:
    text = f'variable "{name}" {{\n  sensitive = true\n  default = "{value}"\n}}\n'
    (hint,) = _scan(tmp_path, {"variables.tf": text}).secret_hints
    assert (hint.kind == "hardcoded") is hardcoded
    if hardcoded:
        assert value not in (hint.evidence_text or "")


@pytest.mark.parametrize(
    "rule, kinds",
    [
        ('api_groups = [""]\n    resources = ["events"]\n    verbs = ["*"]', []),
        ('api_groups = ["metrics.k8s.io"]\n    resources = ["*"]\n    verbs = ["get", "list"]', []),
        ('api_groups = [""]\n    resources = ["pods"]\n    verbs = ["*"]', ["rbac_wildcard"]),
        ('api_groups = [""]\n    resources = ["secrets"]\n    resource_names = ["tls"]\n    verbs = ["get"]', []),
        ('api_groups = [""]\n    resources = ["secrets"]\n    verbs = ["get"]', ["rbac_secret_access"]),
    ],
)
def test_kubernetes_provider_rbac_filters(tmp_path: Path, rule: str, kinds: list) -> None:
    text = f'resource "kubernetes_cluster_role" "r" {{\n  rule {{\n    {rule}\n  }}\n}}\n'
    assert [m.kind for m in _records(tmp_path, text)] == kinds


@pytest.mark.parametrize("role, count", [("system:basic-user", 0), ("view", 0), ("edit", 1), ("cluster-admin", 1)])
def test_kubernetes_provider_broad_group_binding_needs_admin_role(tmp_path: Path, role: str, count: int) -> None:
    text = (
        f'resource "kubernetes_cluster_role_binding" "b" {{\n  role_ref {{\n    name = "{role}"\n  }}\n'
        '  subject {\n    kind = "Group"\n    name = "system:authenticated"\n  }\n}\n'
    )
    assert len(_records(tmp_path, text)) == count


@pytest.mark.parametrize(
    "annotation, exposed",
    [
        ('"service.beta.kubernetes.io/aws-load-balancer-internal" = "true"', False),
        ('"service.beta.kubernetes.io/aws-load-balancer-internal" = "false"', True),
        ('"service.beta.kubernetes.io/aws-load-balancer-scheme" = "internet-facing"', True),
        ('"service.beta.kubernetes.io/aws-load-balancer-scheme" = "internal"', False),
        ('"service.beta.kubernetes.io/azure-load-balancer-internal" = var.internal', False),
    ],
)
def test_kubernetes_provider_internal_lb_annotations(tmp_path: Path, annotation: str, exposed: bool) -> None:
    text = (
        f'resource "kubernetes_service" "s" {{\n  metadata {{\n    annotations = {{\n      {annotation}\n    }}\n  }}\n'
        '  spec {\n    type = "LoadBalancer"\n  }\n}\n'
    )
    assert bool(_records(tmp_path, text, "exposed_service")) is exposed


@pytest.mark.parametrize("path, severity", [("/etc/ssl/certs", "low"), ("/etc/letsencrypt", "low"), ("/dev/dri", "low"),
                                            ("/dev/log", "low"), ("/etc/kubernetes", "high")])
def test_kubernetes_provider_benign_host_paths(tmp_path: Path, path: str, severity: str) -> None:
    text = f'resource "kubernetes_pod" "p" {{\n  spec {{\n    volume {{\n      host_path {{\n        path = "{path}"\n      }}\n    }}\n  }}\n}}\n'
    assert [m.severity for m in _records(tmp_path, text, "host_path_mount")] == [severity]


def test_v2_default_route_on_http_and_websocket_apis(tmp_path: Path) -> None:
    text = (
        'resource "aws_apigatewayv2_api" "http" {\n  protocol_type = "HTTP"\n}\n'
        'resource "aws_apigatewayv2_api" "ws" {\n  protocol_type = "WEBSOCKET"\n}\n'
        'resource "aws_apigatewayv2_route" "catch_all" {\n  api_id = aws_apigatewayv2_api.http.id\n  route_key = "$default"\n}\n'
        'resource "aws_apigatewayv2_route" "guarded" {\n  api_id = aws_apigatewayv2_api.http.id\n  route_key = "$default"\n'
        '  authorization_type = "JWT"\n}\n'
        'resource "aws_apigatewayv2_route" "ws_default" {\n  api_id = aws_apigatewayv2_api.ws.id\n  route_key = "$default"\n}\n'
    )
    result = _scan(tmp_path, {"main.tf": text})
    records = [m.resource for m in result.cloud_misconfigs if m.kind == "api_no_authorizer"]
    assert records == ["aws_apigatewayv2_route.catch_all"]
    assert {(r.path, r.method) for r in result.routes} == {("/{proxy+}", "ANY")}


def test_old_core_gets_no_records_and_keeps_hints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from attackmap_analyzer_terraform import analyzer

    monkeypatch.setattr(analyzer, "_CLOUD_RECORDS", False)
    result = _scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket_acl" "a" {\n  acl = "public-read"\n}\n'})
    assert result.cloud_misconfigs == []
    assert "s3_public_acl:a" in {h.hint for h in result.entrypoint_hints}


_COMMENTED_TF = '''# Stray braces and quotes in comments: { "
resource "aws_instance" "a" {
  # TODO: drop the public IP {
  // was "public
  /* old: ingress { cidr = "0.0.0.0/0" */
  associate_public_ip_address = true
  user_data = <<-EOT
    #!/bin/sh
    echo '{' > /tmp/x "
  EOT
}

resource "aws_db_instance" "db" {
  storage_encrypted = false
}

# resource "aws_instance" "commented_out" {
#   associate_public_ip_address = true
# }

resource "aws_instance" "b" {
  associate_public_ip_address = true
}
'''


def test_comments_strings_and_heredocs_do_not_swallow_later_blocks(tmp_path: Path) -> None:
    records = {(m.kind, m.resource) for m in _records(tmp_path, _COMMENTED_TF)}
    assert records == {
        ("public_network_access", "aws_instance.a"),
        ("unencrypted_storage", "aws_db_instance.db"),
        ("public_network_access", "aws_instance.b"),
    }


def test_an_unterminated_block_does_not_hide_later_blocks(tmp_path: Path) -> None:
    text = (
        'resource "aws_instance" "broken" {\n  associate_public_ip_address = true\n\n'
        'resource "aws_db_instance" "db" {\n  storage_encrypted = false\n}\n'
    )
    records = {(m.kind, m.resource) for m in _records(tmp_path, text)}
    assert ("unencrypted_storage", "aws_db_instance.db") in records
    assert ("public_network_access", "aws_instance.broken") in records


def test_heredoc_policy_statements_are_found(tmp_path: Path) -> None:
    text = (
        'resource "aws_iam_role_policy" "p" {\n  policy = <<EOF\n'
        '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}\nEOF\n}\n'
    )
    hints = {h.hint for h in _scan(tmp_path, {"main.tf": text}).auth_hints}
    assert {"iam_wildcard_action:p", "iam_wildcard_resource:p"} <= hints
