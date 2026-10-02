"""Terraform / HCL infrastructure-as-code analyzer for AttackMap.

This analyzer is shaped differently from language analyzers — Terraform doesn't
have routes in the application sense. Instead, the value is in:

- **Public ingress** — security groups (open CIDRs in `ingress` only; open
  egress is ignored) / Lambda function URLs / API Gateway methods with no
  auth / public S3 ACLs and bucket policies → `entrypoint_hints`
- **Asset inventory** — S3 buckets, RDS, DynamoDB, Cognito user pools, KMS keys
  → `service_hints` and `database_hints`
- **Secrets** — `aws_secretsmanager_secret`, `aws_ssm_parameter` (SecureString),
  `variable` blocks marked `sensitive = true` or with secret-shaped names,
  and secret-shaped string literals in `.tfvars` (`kind="hardcoded"`)
  → `secret_hints`
- **IAM blast radius** — `Action "*"`, `Resource "*"` and Allow-`Principal "*"`
  in `aws_iam_*` policies, role trust policies and `aws_iam_policy_document`
  data sources → `auth_hints`
- **Database engines** — `aws_db_instance.engine = "postgres"` → `database_hints`
  with the engine as the kind

All emissions populate Signal v2 fields (line numbers, evidence snippets) so
downstream insights can cite `infra/main.tf:NN`.

`.tf.json` files are parsed with `json` and each block is rendered back to HCL
and sent through the same handlers, so both syntaxes yield the same signals.

HCL parsing uses brace-depth counting on top of regex. This is approximate but
sufficient for the resource-level introspection the analyzer needs. Variable
interpolation (`${var.foo}`) is not resolved — string literals and direct
attribute values are what we extract.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from attackmap.sdk import DEFAULT_SKIP_DIRS, iter_repo_files, line_of, read_source, rel

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
# Terraform's provider/module cache on top of the shared skip list (which
# already covers .git/, node_modules/, vendor/, ...). Matched against directory
# names *inside* the repo only.
SKIP_DIRS = DEFAULT_SKIP_DIRS | {".terraform"}
# ``.tf.json`` can't be expressed as a single suffix, so walk ``.json`` too and
# narrow with ``_is_terraform_file``.
_WALK_SUFFIXES = {".tf", ".tfvars", ".json"}
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


def _is_terraform_file(path: Path) -> bool:
    return path.suffix == ".tf" or path.name.endswith(".tf.json") or path.suffix == ".tfvars"


def _line_snippet(content: str, offset: int, *, max_chars: int = _SNIPPET_MAX_CHARS) -> str:
    # Kept local rather than ``attackmap.sdk.line_snippet(content, line_of(...))``:
    # the SDK helper indexes ``str.splitlines()``, which also breaks on form
    # feeds and lone ``\r``, so its line numbering can disagree with
    # ``line_of`` (which counts ``\n`` only).
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


def _scan_text(text: str) -> tuple[list[int], list[bool]]:
    """Per-character brace depth and string mask for ``text``.

    ``depths[i]`` is the ``{ }`` nesting depth of the code around character
    ``i`` (an opening ``{`` and its matching ``}`` both carry the outer depth);
    ``in_string[i]`` is True for characters of a ``"..."`` literal, quotes
    included. Braces inside strings don't count."""
    depths = [0] * len(text)
    in_string = [False] * len(text)
    depth = 0
    inside = False
    escape = False
    for i, ch in enumerate(text):
        if inside:
            in_string[i] = True
            depths[i] = depth
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                inside = False
            continue
        if ch == '"':
            inside = True
            in_string[i] = True
        elif ch == "}":
            depth = max(depth - 1, 0)
        depths[i] = depth
        if ch == "{":
            depth += 1
    return depths, in_string


def _top_level(body: str) -> str:
    """``body`` with the contents of every nested ``{ ... }`` removed (the
    braces themselves are kept), so attribute lookups only see the block's own
    attributes and not those of nested blocks or object values."""
    depths, _ = _scan_text(body)
    return "".join(ch for ch, d in zip(body, depths) if d == 0)


def _at_top(depths: list[int], in_string: list[bool], text: str, i: int) -> bool:
    """True if a token starting at ``i`` is top-level code (or the opening
    quote of a top-level string key)."""
    if depths[i] != 0:
        return False
    if not in_string[i]:
        return True
    return text[i] == '"' and (i == 0 or not in_string[i - 1])


def _extract_attr(body: str, name: str) -> str | None:
    """Return the value of a top-level attribute `name = ...` in a block body
    (does not descend into nested blocks). Strips matching quotes."""
    top = _top_level(body)
    pattern = re.compile(rf'^\s*{re.escape(name)}\s*=\s*"([^"]*)"\s*$', re.MULTILINE)
    match = pattern.search(top)
    if match:
        return match.group(1)
    # Try unquoted form (booleans, references, numbers, lists)
    raw_pattern = re.compile(rf'^\s*{re.escape(name)}\s*=\s*([^\n]+?)\s*$', re.MULTILINE)
    match = raw_pattern.search(top)
    if match:
        return match.group(1).strip()
    return None


def _sub_blocks(body: str, name: str) -> list[str]:
    """Bodies of the nested blocks called ``name`` directly inside ``body``.

    Covers ``name { ... }``, ``dynamic "name" { ... }`` and the
    attributes-as-blocks form ``name = [{ ... }, { ... }]``. Blocks nested
    deeper than one level are not returned."""
    depths, in_string = _scan_text(body)
    header = re.compile(rf'(?:(?<![\w.]){re.escape(name)}|\bdynamic\s+"{re.escape(name)}")\s*(\{{|=\s*\[)')
    blocks: list[str] = []
    for match in header.finditer(body):
        if not _at_top(depths, in_string, body, match.start()):
            continue
        if match.group(1) == "{":
            inner, _ = _block_body(body, match.end())
            blocks.append(inner)
            continue
        i = match.end()
        while i < len(body):
            ch = body[i]
            if depths[i] == 0 and not in_string[i] and ch == "]":
                break
            if depths[i] == 0 and not in_string[i] and ch == "{":
                inner, end = _block_body(body, i + 1)
                blocks.append(inner)
                i = end + 1
                continue
            i += 1
    return blocks


def _attr_value(text: str, key: str) -> str | None:
    """Raw value of ``key = value`` / ``"key": value`` at the top level of
    ``text`` (case-insensitive key). Returns the string literal, the whole
    ``[...]`` list or the whole ``{...}`` object, or None when absent."""
    depths, in_string = _scan_text(text)
    pattern = re.compile(rf'(?<![\w.])"?{re.escape(key)}"?\s*[:=](?!=)\s*', re.IGNORECASE)
    for match in pattern.finditer(text):
        if not _at_top(depths, in_string, text, match.start()):
            continue
        i = match.end()
        if i >= len(text):
            return None
        ch = text[i]
        if ch == '"':
            end = i + 1
            while end < len(text) and not (text[end] == '"' and text[end - 1] != "\\"):
                end += 1
            return text[i : end + 1]
        if ch == "{":
            inner, _ = _block_body(text, i + 1)
            return "{" + inner + "}"
        heredoc = _HEREDOC_RE.match(text, i)
        if heredoc:
            marker = heredoc.group(1)
            terminator = re.compile(rf"^[ \t]*{re.escape(marker)}[ \t]*$", re.MULTILINE)
            end = terminator.search(text, heredoc.end())
            return text[i : end.end() if end else len(text)]
        # Lists, function calls (`jsonencode({...})`), references: read up to
        # the end of the line or a top-level `,` (one-line objects), extended
        # across balanced ( [ { and strings.
        level = 0
        quoted = False
        end = i
        while end < len(text):
            c = text[end]
            if quoted:
                if c == "\\":
                    end += 2
                    continue
                if c == '"':
                    quoted = False
            elif c == '"':
                quoted = True
            elif c in "([{":
                level += 1
            elif c in ")]}":
                level -= 1
                if level < 0:
                    break
            elif c in "\n," and level == 0:
                break
            end += 1
        return text[i:end].strip()
    return None


_HEREDOC_RE = re.compile(r"<<-?\s*([A-Za-z_]\w*)[ \t]*\n")
_WILDCARD_RE = re.compile(r'"\*"')


def _has_wildcard(value: str | None) -> bool:
    """True if ``value`` (a string literal, list or object) contains the bare
    ``"*"`` element. ``"s3:*"`` and similar service wildcards don't count."""
    return value is not None and _WILDCARD_RE.search(value) is not None


def _has_open_cidr(body: str) -> bool:
    """True if the body references an open CIDR (`0.0.0.0/0` or `::/0`)
    as a list element."""
    return '"0.0.0.0/0"' in body or '"::/0"' in body


def _has_open_ingress(sg_body: str) -> bool:
    """True if any ``ingress`` sub-block of an ``aws_security_group`` allows
    an open CIDR. Open ``egress`` (the near-universal default) is ignored."""
    return any(_has_open_cidr(block) for block in _sub_blocks(sg_body, "ingress"))


_STATEMENT_KEY_RE = re.compile(
    r'(?<![\w.])"?(?:Effect|Action|NotAction|Principal|NotPrincipal)"?\s*[:=](?!=)', re.IGNORECASE,
)


def _json_policy_statements(text: str) -> list[str]:
    """Bodies of IAM policy statement objects found anywhere in ``text``
    (``jsonencode({...})``, heredoc JSON or a JSON string rendered as a
    heredoc). A statement is any ``{ ... }`` whose own keys include Effect,
    Action, NotAction, Principal or NotPrincipal (case-insensitive)."""
    _, in_string = _scan_text(text)
    statements: list[str] = []
    for i, ch in enumerate(text):
        if ch != "{" or in_string[i]:
            continue
        inner, _ = _block_body(text, i + 1)
        if _STATEMENT_KEY_RE.search(_top_level(inner)):
            statements.append(inner)
    return statements


def _statement_is_deny(effect: str | None) -> bool:
    return (effect or "").strip().strip('"').lower() == "deny"


class _PolicyFindings:
    __slots__ = ("wildcard_action", "wildcard_resource", "public_principal")

    def __init__(self) -> None:
        self.wildcard_action = False
        self.wildcard_resource = False
        # Allow + Principal "*" with no Condition: anyone can use it.
        self.public_principal = False


def _scan_json_policies(text: str) -> _PolicyFindings:
    findings = _PolicyFindings()
    for statement in _json_policy_statements(text):
        if _statement_is_deny(_attr_value(statement, "Effect")):
            continue
        if _has_wildcard(_attr_value(statement, "Action")):
            findings.wildcard_action = True
        if _has_wildcard(_attr_value(statement, "Resource")):
            findings.wildcard_resource = True
        if _has_wildcard(_attr_value(statement, "Principal")) and _attr_value(statement, "Condition") is None:
            findings.public_principal = True
    return findings


def _scan_policy_document(body: str) -> _PolicyFindings:
    """``data "aws_iam_policy_document"``: HCL ``statement { ... }`` blocks."""
    findings = _PolicyFindings()
    for statement in _sub_blocks(body, "statement"):
        if _statement_is_deny(_extract_attr(statement, "effect")):
            continue
        top = _top_level(statement)
        if _has_wildcard(_attr_value(top, "actions")):
            findings.wildcard_action = True
        if _has_wildcard(_attr_value(top, "resources")):
            findings.wildcard_resource = True
        if not _sub_blocks(statement, "condition"):
            for principals in _sub_blocks(statement, "principals"):
                if _has_wildcard(_attr_value(principals, "identifiers")) or _has_wildcard(
                    _attr_value(principals, "type")
                ):
                    findings.public_principal = True
    return findings


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


_PUBLIC_S3_ACLS = {"public-read", "public-read-write"}
_IAM_POLICY_RESOURCES = {
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "aws_iam_role",
}

# `key = "literal"` in a .tfvars file (string values only; numbers/bools are
# never credentials and references aren't allowed in tfvars).
_TFVARS_ASSIGN_RE = re.compile(r'^[ \t]*([A-Za-z_][\w-]*)[ \t]*=[ \t]*"((?:[^"\\\n]|\\.)*)"', re.MULTILINE)
# Secret-shaped names whose value is an identifier/locator, not a credential
# (`kms_key_id`, `ssh_key_name`, `secret_arn`, `token_ttl`, ...).
_NON_SECRET_LAST_TOKENS = {
    "name", "names", "id", "ids", "arn", "arns", "path", "file", "type", "length",
    "size", "version", "count", "enabled", "enable", "days", "period", "ttl",
    "alias", "prefix", "suffix", "region", "rotation", "policy", "usage", "spec",
}


def _tfvars_key_is_secret(key: str) -> bool:
    if not _looks_secret_shaped(key):
        return False
    last = re.split(r"[_-]", key.lower())[-1]
    return last not in _NON_SECRET_LAST_TOKENS


def _looks_like_reference(value: str) -> bool:
    return value.startswith(("${", "arn:"))


def _json_objects(value: object) -> list[dict]:
    """Terraform JSON lets any block level be an object or a list of objects."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _json_scalar_to_hcl(value: object) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if "\n" in value or (stripped.startswith(("{", "${")) and '"' in value):
            # Embedded policy JSON / `${jsonencode(...)}`: emit as a heredoc so
            # the policy scanners see its structure, not an escaped string.
            try:
                parsed = json.loads(value)
            except ValueError:
                text = value
            else:
                text = json.dumps(parsed, indent=2)
            return f"<<EOT\n{text}\nEOT"
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return json.dumps(value)


def _json_to_hcl(obj: dict, indent: int = 0) -> str:
    """Render a Terraform JSON block body as HCL. Object values and lists of
    objects become nested blocks (how Terraform JSON spells `ingress { }`,
    `statement { }`, ...); everything else is an attribute."""
    pad = "  " * indent
    lines: list[str] = []
    for key, value in obj.items():
        blocks = _json_objects(value)
        if blocks and (isinstance(value, dict) or len(blocks) == len(value)):
            for block in blocks:
                lines.append(f"{pad}{key} {{")
                lines.append(_json_to_hcl(block, indent + 1))
                lines.append(f"{pad}}}")
        else:
            lines.append(f"{pad}{key} = {_json_scalar_to_hcl(value)}")
    return "\n".join(lines)


class _JsonLocator:
    """Find the source offset of a JSON object key, scanning forward so that
    repeated names (same resource name under two types) resolve in order."""

    def __init__(self, content: str) -> None:
        self.content = content
        self.pos = 0

    def find(self, key: str, *, from_start: bool = False) -> int:
        if from_start:
            self.pos = 0
        pattern = re.compile(r'"' + re.escape(key) + r'"\s*:')
        match = pattern.search(self.content, self.pos) or pattern.search(self.content)
        if match is None:
            return self.pos
        self.pos = match.end()
        return match.start()


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
        for path in iter_repo_files(root, suffixes=_WALK_SUFFIXES, skip_dirs=SKIP_DIRS):
            if _is_terraform_file(path):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        for file_path in iter_repo_files(root, suffixes=_WALK_SUFFIXES, skip_dirs=SKIP_DIRS):
            if not _is_terraform_file(file_path):
                continue
            content = read_source(file_path)
            if content is None:
                continue

            result.files_scanned += 1
            if "hcl" not in result.languages:
                result.languages.append("hcl")

            relative = rel(file_path, root)
            if file_path.name.endswith(".tf.json"):
                self._analyze_tf_json(content, relative, result)
                continue
            if file_path.suffix == ".tfvars":
                self._extract_tfvars_secrets(content, relative, result)
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
            self._handle_provider(
                match.group(1), relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                result,
            )

    def _extract_resources(self, content: str, relative: str, result: ScanResult) -> None:
        for match in RESOURCE_BLOCK_PATTERN.finditer(content):
            resource_type, resource_name = match.group(1), match.group(2)
            body, _ = _block_body(content, match.end())
            line = line_of(content, match.start())
            self._dispatch_resource(
                resource_type, resource_name, body, relative, line,
                _line_snippet(content, match.start()), result,
            )

    def _extract_variables(self, content: str, relative: str, result: ScanResult) -> None:
        for match in VARIABLE_BLOCK_PATTERN.finditer(content):
            body, _ = _block_body(content, match.end())
            self._handle_variable(
                match.group(1), body, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                result,
            )

    def _extract_modules(self, content: str, relative: str, result: ScanResult) -> None:
        for match in MODULE_BLOCK_PATTERN.finditer(content):
            self._append_unique_service(result, f"module:{match.group(1)}", relative)

    def _extract_data_sources(self, content: str, relative: str, result: ScanResult) -> None:
        for match in DATA_BLOCK_PATTERN.finditer(content):
            body, _ = _block_body(content, match.end())
            self._handle_data_source(
                match.group(1), match.group(2), body, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                result,
            )

    def _extract_tfvars_secrets(self, content: str, relative: str, result: ScanResult) -> None:
        """``.tfvars`` assign values to variables: a secret-shaped key with a
        non-empty string literal is a credential committed to the repo."""
        depths, in_string = _scan_text(content)
        for match in _TFVARS_ASSIGN_RE.finditer(content):
            if not _at_top(depths, in_string, content, match.start(1)):
                continue
            key, value = match.group(1), match.group(2)
            if not value.strip() or not _tfvars_key_is_secret(key) or _looks_like_reference(value):
                continue
            line = line_of(content, match.start(1))
            self._append_unique_secret(
                result, key, relative, line,
                # Never echo the literal itself into the report.
                f'{key} = "<redacted>"',
                kind="hardcoded",
            )

    def _analyze_tf_json(self, content: str, relative: str, result: ScanResult) -> None:
        """Terraform JSON syntax (``*.tf.json``, e.g. CDKTF output). Each block
        is rendered back to HCL and sent through the same handlers as ``.tf``
        files, with line/evidence taken from the JSON source."""
        try:
            document = json.loads(content)
        except ValueError:
            return
        if not isinstance(document, dict):
            return
        locator = _JsonLocator(content)
        locator.find("provider")

        for provider_obj in _json_objects(document.get("provider")):
            for provider in provider_obj:
                offset = locator.find(provider)
                self._handle_provider(
                    provider, relative, line_of(content, offset), _line_snippet(content, offset), result,
                )
        for kind in ("resource", "data"):
            locator.find(kind, from_start=True)
            for type_obj in _json_objects(document.get(kind)):
                for block_type, named in type_obj.items():
                    locator.find(block_type)
                    for named_obj in _json_objects(named):
                        for block_name, raw_body in named_obj.items():
                            offset = locator.find(block_name)
                            line = line_of(content, offset)
                            ev = _line_snippet(content, offset)
                            for body_obj in _json_objects(raw_body):
                                body = _json_to_hcl(body_obj)
                                if kind == "resource":
                                    self._dispatch_resource(block_type, block_name, body, relative, line, ev, result)
                                else:
                                    self._handle_data_source(block_type, block_name, body, relative, line, ev, result)
        locator.find("variable", from_start=True)
        for var_obj in _json_objects(document.get("variable")):
            for var_name, raw_body in var_obj.items():
                offset = locator.find(var_name)
                for body_obj in _json_objects(raw_body) or [{}]:
                    self._handle_variable(
                        var_name, _json_to_hcl(body_obj), relative,
                        line_of(content, offset), _line_snippet(content, offset), result,
                    )
        for module_obj in _json_objects(document.get("module")):
            for module_name in module_obj:
                self._append_unique_service(result, f"module:{module_name}", relative)

    # ---------- Block handlers (shared by HCL and JSON syntax) ----------

    def _handle_provider(self, provider: str, file: str, line: int, ev: str, result: ScanResult) -> None:
        label = _PROVIDER_LABEL.get(provider, f"terraform-{provider}")
        self._append_unique_framework(result, label, file, line, ev)

    def _handle_variable(self, var_name: str, body: str, file: str, line: int, ev: str, result: ScanResult) -> None:
        sensitive = (_extract_attr(body, "sensitive") or "").lower() == "true"
        if sensitive or _looks_secret_shaped(var_name):
            self._append_unique_secret(result, var_name, file, line, ev)

    def _handle_data_source(
        self, data_type: str, data_name: str, body: str, file: str, line: int, ev: str, result: ScanResult,
    ) -> None:
        # data "aws_secretsmanager_secret" "x" { ... } — surface secret references via data.
        if data_type in {"aws_secretsmanager_secret", "aws_secretsmanager_secret_version", "aws_ssm_parameter"}:
            self._append_unique_secret(result, f"data:{data_type}:{data_name}", file, line, ev)
            return
        if data_type == "aws_iam_policy_document":
            self._emit_policy_findings(_scan_policy_document(body), data_name, file, line, ev, result)

    def _emit_policy_findings(
        self, findings: _PolicyFindings, name: str, file: str, line: int, ev: str, result: ScanResult,
    ) -> None:
        if findings.wildcard_action:
            self._append_unique_auth(result, f"iam_wildcard_action:{name}", file, line, ev, 0.7)
        if findings.wildcard_resource:
            # Resource "*" with scoped actions is common (Describe*, logs), so
            # this is a weaker smell than a wildcard action.
            self._append_unique_auth(result, f"iam_wildcard_resource:{name}", file, line, ev, 0.5)
        if findings.public_principal:
            self._append_unique_auth(result, f"iam_wildcard_principal:{name}", file, line, ev, 0.7)

    # ---------- Resource dispatchers ----------

    def _dispatch_resource(
        self,
        resource_type: str,
        resource_name: str,
        body: str,
        file: str,
        line: int,
        ev: str,
        result: ScanResult,
    ) -> None:
        # ---- AWS ----
        if resource_type == "aws_security_group":
            if _has_open_ingress(body):
                self._append_unique_entrypoint(
                    result, f"sg_open_ingress:{resource_name}", file, line, ev,
                )
            return
        if resource_type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"} and _has_open_cidr(body):
            direction = (_extract_attr(body, "type") or "").lower() or "ingress"
            if direction == "egress":
                # Open egress is the default posture, not exposure.
                return
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
            # AWS provider <= v3 inline `acl` / `policy` arguments.
            acl = (_extract_attr(body, "acl") or "").lower()
            if acl in _PUBLIC_S3_ACLS:
                self._append_unique_entrypoint(
                    result, f"s3_public_acl:{resource_name}", file, line, ev,
                )
            if _scan_json_policies(_attr_value(body, "policy") or "").public_principal:
                self._append_unique_entrypoint(
                    result, f"s3_public_policy:{resource_name}", file, line, ev,
                )
            return
        if resource_type == "aws_s3_bucket_policy":
            if _scan_json_policies(body).public_principal:
                self._append_unique_entrypoint(
                    result, f"s3_public_policy:{resource_name}", file, line, ev,
                )
            return
        if resource_type == "aws_s3_bucket_acl":
            acl = (_extract_attr(body, "acl") or "").lower()
            if acl in _PUBLIC_S3_ACLS:
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
        if resource_type in _IAM_POLICY_RESOURCES:
            # Identity policies (Action/Resource) and, for aws_iam_role, the
            # assume_role_policy trust document (Principal) plus inline_policy.
            self._emit_policy_findings(_scan_json_policies(body), resource_name, file, line, ev, result)
            return

        # ---- Azure ----
        if resource_type == "azurerm_storage_account":
            self._append_unique_service(result, f"azure_storage:{resource_name}", file)
            return
        if resource_type == "azurerm_key_vault":
            self._append_unique_service(result, f"key_vault:{resource_name}", file)
            return
        if (
            resource_type == "azurerm_network_security_rule"
            and _has_open_cidr(body)
            and (_extract_attr(body, "direction") or "inbound").lower() != "outbound"
        ):
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
        if (
            resource_type == "google_compute_firewall"
            and _has_open_cidr(body)
            and (_extract_attr(body, "direction") or "ingress").lower() != "egress"
        ):
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
    def _append_unique_secret(
        result: ScanResult,
        name: str,
        file: str,
        line: int | None,
        evidence: str | None,
        *,
        kind: str | None = None,
    ) -> None:
        key = (name, file)
        if any((item.name, item.file) == key for item in result.secret_hints):
            return
        extra = {"kind": kind} if kind is not None else {}
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85, **extra)
        )

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
