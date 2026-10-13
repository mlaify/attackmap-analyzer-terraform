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
- **Misconfigurations** (#4) — unpinned module sources, public endpoints and
  data, missing authorizers, unencrypted storage, kubernetes provider pods /
  RBAC / services → `cloud_misconfigs` (core's `CloudMisconfig` record, which
  becomes a finding). Records carry `for_each`/`count` and, for resources in a
  local module, the calling `module` blocks.

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
import posixpath
import re
from pathlib import Path

from bisect import bisect_right

from attackmap.sdk import (
    DEFAULT_SKIP_DIRS,
    AnalyzerMetadata,
    AuthHint,
    CloudMisconfig,
    DatabaseHint,
    EntrypointHint,
    ExternalCall,
    FrameworkHint,
    iter_repo_files,
    read_source,
    rel,
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


# ---------- Linear-time bookkeeping (hostile input) ----------

# Dedup keys per result: a linear `any(...)` scan per append is quadratic on
# a file with tens of thousands of blocks. Keyed by id(); the result object
# is kept to rule out id reuse, and dropped at the end of `analyze`.
_SEEN: dict[int, tuple[object, set]] = {}

# Feature detection: a core older than AttackMap#334 neither exports the
# record nor has the field, and ignores records. The pre-existing exposure
# hints (s3_public_*, rds_publicly_accessible, apigw*_open, ...) are emitted
# on every core either way.
_CLOUD_RECORDS = CloudMisconfig is not None and "cloud_misconfigs" in getattr(ScanResult, "model_fields", {})


def _first_seen(owner: object, key: tuple) -> bool:
    entry = _SEEN.get(id(owner))
    if entry is None or entry[0] is not owner:
        entry = _SEEN[id(owner)] = (owner, set())
    if key in entry[1]:
        return False
    entry[1].add(key)
    return True


# Line starts of the file being analyzed. `attackmap.sdk.line_of` recounts
# newlines from the top on every call (quadratic for many blocks); files are
# analyzed one at a time, so one cached index is enough.
_LINES: list = [None, [0]]


def line_of(content: str, offset: int) -> int:
    """1-indexed line of ``offset`` (same numbering as `attackmap.sdk.line_of`)."""
    if _LINES[0] is not content:
        starts = [0]
        index = content.find("\n")
        while index != -1:
            starts.append(index + 1)
            index = content.find("\n", index + 1)
        _LINES[0], _LINES[1] = content, starts
    return bisect_right(_LINES[1], max(offset, 0))

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


def _skip_non_code(content: str, i: int) -> int | None:
    """If a comment (``#``, ``//``, ``/* */``) or heredoc starts at ``i``,
    the offset just past it; else None. Braces and quotes in them don't
    count (a stray ``{`` in a comment used to swallow the rest of the file)."""
    ch = content[i]
    if ch == "#" or content.startswith("//", i):
        end = content.find("\n", i)
        return len(content) if end == -1 else end
    if content.startswith("/*", i):
        end = content.find("*/", i + 2)
        return len(content) if end == -1 else end + 2
    if content.startswith("<<", i):
        heredoc = _HEREDOC_RE.match(content, i)
        if heredoc:
            terminator = re.compile(rf"^[ \t]*{re.escape(heredoc.group(1))}[ \t]*$", re.MULTILINE)
            end = terminator.search(content, heredoc.end())
            return len(content) if end is None else end.end()
    return None


def _brace_pairs(content: str) -> tuple[dict[int, int], bytearray]:
    """One linear pass: the closing ``}`` of every code ``{``, and a mask of
    the characters inside comments, heredocs and strings. Strings end at a
    newline (HCL quoted strings are single-line), so a stray ``"`` can't
    swallow the file either."""
    closes: dict[int, int] = {}
    ignored = bytearray(len(content))
    stack: list[int] = []
    i, n = 0, len(content)
    while i < n:
        ch = content[i]
        if ch == '"':
            j = i + 1
            while j < n and content[j] not in '"\n':
                j += 2 if content[j] == "\\" else 1
            end = min(j + 1, n)
            ignored[i:end] = b"\x01" * (end - i)
            i = end
            continue
        skipped = _skip_non_code(content, i) if ch in "#/<" else None
        if skipped is not None:
            ignored[i:skipped] = b"\x01" * (skipped - i)
            i = skipped
            continue
        if ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            closes[stack.pop()] = i
        i += 1
    return closes, ignored


def _top_blocks(pattern: re.Pattern[str], content: str):
    """``(match, body)`` for each block header ``pattern`` finds outside
    comments and strings. Top-level blocks don't nest, so headers inside a
    terminated block are skipped. An unterminated block's body ends at the
    next header, and scanning resumes after its own header, so one broken
    block no longer hides the rest of the file. Linear overall."""
    closes, ignored = _brace_pairs(content)
    headers = [m for m in pattern.finditer(content) if not ignored[m.start()]]
    resume = 0
    for index, match in enumerate(headers):
        if match.start() < resume:
            continue
        close = closes.get(match.end() - 1)
        if close is None:
            end = headers[index + 1].start() if index + 1 < len(headers) else len(content)
            yield match, content[match.end():end]
            resume = match.end()
        else:
            yield match, content[match.end():close]
            resume = close + 1


def _block_body(content: str, body_start: int, *, heredocs: bool = True) -> tuple[str, int]:
    """Return the body of a block whose `{` is at body_start-1, plus the offset
    of the closing `}`. Tracks brace depth, string literals, comments and
    (with ``heredocs``) heredocs, so nested `ingress { ... }` blocks are
    included and a `{` in a comment doesn't count. ``heredocs`` must match
    the `_scan_text` mode of the caller."""
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
            if ch in "#/<" and (heredocs or ch != "<"):
                skipped = _skip_non_code(content, i)
                if skipped is not None:
                    i = skipped
                    continue
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


def _scan_text(text: str, *, heredocs: bool = True) -> tuple[list[int], list[bool]]:
    """Per-character brace depth and string mask for ``text``.

    ``depths[i]`` is the ``{ }`` nesting depth of the code around character
    ``i`` (an opening ``{`` and its matching ``}`` both carry the outer depth);
    ``in_string[i]`` is True for characters of a ``"..."`` literal (quotes
    included), a comment, or (with ``heredocs``) a heredoc body. Braces in
    any of them don't count. Policy scanning passes ``heredocs=False`` to see
    the JSON inside a heredoc."""
    depths = [0] * len(text)
    in_string = [False] * len(text)
    depth = 0
    inside = False
    escape = False
    skip_to = 0
    for i, ch in enumerate(text):
        if i < skip_to:
            in_string[i] = True
            depths[i] = depth
            continue
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
        if ch in "#/<" and (heredocs or ch != "<"):
            skipped = _skip_non_code(text, i)
            if skipped is not None:
                skip_to = skipped
                in_string[i] = True
                depths[i] = depth
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


_POLICY_MAX_DEPTH = 8


def _json_policy_statements(text: str) -> list[str]:
    """Bodies of IAM policy statement objects found anywhere in ``text``
    (``jsonencode({...})``, heredoc JSON or a JSON string rendered as a
    heredoc). A statement is any ``{ ... }`` whose own keys include Effect,
    Action, NotAction, Principal or NotPrincipal (case-insensitive)."""
    depths, in_string = _scan_text(text, heredocs=False)
    statements: list[str] = []
    for i, ch in enumerate(text):
        # Statements sit a few levels deep (jsonencode({ Statement = [{...}] })).
        # Bounding the depth keeps this linear: every `{` used to re-scan its
        # whole body, quadratic in nesting.
        if ch != "{" or in_string[i] or depths[i] > _POLICY_MAX_DEPTH:
            continue
        inner, _ = _block_body(text, i + 1, heredocs=False)
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


# `default = "literal"` in a variable block (heredoc / list / map defaults are
# not credentials).
_VARIABLE_STRING_DEFAULT_RE = re.compile(r'^[ \t]*default[ \t]*=[ \t]*"((?:[^"\\\n]|\\.)*)"', re.MULTILINE)


_PUBLIC_KEY_PREFIXES = ("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-", "sk-ssh-", "-----BEGIN PUBLIC KEY", "-----BEGIN CERTIFICATE")
_URL_WITH_PASSWORD_RE = re.compile(r"://[^/@\s:]{1,256}:[^/@\s]{1,256}@")
_PLAIN_WORD_RE = re.compile(r"[A-Za-z]{1,12}")
_IDENTIFIER_NAME_RE = re.compile(r"user|login|account|email|owner", re.IGNORECASE)
_CREDENTIAL_NAME_RE = re.compile(r"pass|pwd|secret|token|private", re.IGNORECASE)
_MIN_CREDENTIAL_LEN = 6


def _credential_shaped_default(name: str, value: str) -> bool:
    """Whether a secret variable's literal default looks like a credential
    rather than a public key, URL, username or short setting (`off`,
    `UserId`, `master`)."""
    value = value.strip()
    if not value or _looks_like_reference(value) or value.startswith(_PUBLIC_KEY_PREFIXES):
        return False
    if "://" in value:
        return bool(_URL_WITH_PASSWORD_RE.search(value))  # only a URL with an embedded password
    if len(value) < _MIN_CREDENTIAL_LEN or _PLAIN_WORD_RE.fullmatch(value):
        return False
    return not (_IDENTIFIER_NAME_RE.search(name) and not _CREDENTIAL_NAME_RE.search(name))


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


# ---------- Module sources (#4) ----------

# go-getter git sources: forced `git::`, scp-like `git@host:`, the GitHub /
# Bitbucket shorthands, or a `.git` repository path.
_GIT_SOURCE_RE = re.compile(r"^(?:git::|git@|(?:github\.com|bitbucket\.org)/)", re.IGNORECASE)
_GIT_SUFFIX_RE = re.compile(r"\.git(?:$|[/?])", re.IGNORECASE)
# Registry address: [<host>/]<namespace>/<name>/<provider>[//<subdir>].
_REGISTRY_SOURCE_RE = re.compile(
    r"^(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/)?[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+(?://[^?]*)?$"
)
_GIT_REF_RE = re.compile(r"[?&]ref=([^&#]+)")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_BRANCH_REFS = frozenset({
    "main", "master", "develop", "development", "dev", "trunk", "head", "latest",
    "stable", "release", "next", "prod", "production", "staging",
})
_MODULE_ESCALATION = "whoever can move that reference changes what `terraform apply` builds, with the deployer's cloud credentials"


def _module_pin_problem(source: str, version: str | None) -> tuple[str, str, float] | None:
    """``(severity, reason, confidence)`` when a remote module source isn't
    pinned to an immutable version, else None. Local paths and other
    getters (s3::, gcs::, http archives) are not judged."""
    src = source.strip()
    if src.startswith(("./", "../")):
        return None
    if _GIT_SOURCE_RE.match(src) or _GIT_SUFFIX_RE.search(src.split("?", 1)[0]):
        ref = _GIT_REF_RE.search(src)
        if ref is None:
            return "medium", "git source without ?ref= follows the default branch", 0.9
        value = ref.group(1)
        if _COMMIT_SHA_RE.match(value):
            return None
        if value.lower() in _BRANCH_REFS:
            return "medium", f"git source pinned to the branch {value!r}", 0.85
        if any(ch.isdigit() for ch in value):
            return None  # a release tag (v1.2.3, 2024.01)
        return "low", f"git ref {value!r} looks like a branch, not a tag or commit", 0.5
    if not src.startswith(("git::", "hg::", "s3::", "gcs::", "http://", "https://")) and _REGISTRY_SOURCE_RE.match(src):
        if not (version or "").strip():
            return "medium", "registry module without a version constraint installs the latest release", 0.9
    return None


_NESTED_BLOCK_RE = re.compile(r'(?m)^[ \t]*(?:[A-Za-z_][\w-]*|dynamic[ \t]+"[^"\n]*")[ \t]*\{')


def _local_module_dir(caller: str, source: str) -> str | None:
    """Repo-relative directory a local ``source`` points at, or None when it
    isn't local or leaves the repo."""
    src = source.strip()
    if not src.startswith(("./", "../")):
        return None
    target = posixpath.normpath(posixpath.join(posixpath.dirname(caller), src.split("//", 1)[0]))
    if target == ".." or target.startswith("../") or target.startswith("/"):
        return None
    return target


def _file_dir(relative: str) -> str:
    return posixpath.dirname(relative) or "."


def _instancing(body: str) -> str | None:
    """``for_each = ...`` / ``count = ...`` of a block, whitespace-folded, so
    a finding can say it applies to every instance."""
    for name in ("for_each", "count"):
        value = _attr_value(_top_level_with_values(body), name)
        if value:
            line = f"{name} = {' '.join(value.split())}"
            return line if len(line) <= 80 else line[:79] + "…"
    return None


def _top_level_with_values(body: str) -> str:
    """``body`` without its nested *blocks* (``name {`` / ``dynamic "x" {``)
    but keeping ``attr = { ... }`` object values, so a ``for_each = {...}``
    is read whole while a nested block's own ``count`` is not."""
    depths, in_string = _scan_text(body)
    keep = [True] * len(body)
    for match in _NESTED_BLOCK_RE.finditer(body):
        start = match.end() - 1  # the `{`
        if depths[match.start()] != 0 or in_string[start]:
            continue
        _, end = _block_body(body, start + 1)
        for i in range(start + 1, min(end, len(body))):
            keep[i] = False
    return "".join(ch for ch, k in zip(body, keep) if k)


# ---------- Misconfiguration helpers (#4) ----------

_PLATFORM_BY_PREFIX = (("aws_", "aws"), ("azurerm_", "azure"), ("google_", "gcp"), ("kubernetes_", "kubernetes"))
_PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
_TRUE_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _platform(resource_type: str) -> str:
    return next((p for prefix, p in _PLATFORM_BY_PREFIX if resource_type.startswith(prefix)), "terraform")


def _is_true(body: str, name: str) -> bool:
    return (_extract_attr(body, name) or "").strip().lower() == "true"


def _is_literal_false(value: str | None) -> bool:
    return (value or "").strip().lower() == "false"


def _public_members(body: str) -> list[str]:
    """``allUsers`` / ``allAuthenticatedUsers`` granted by an IAM member,
    binding (``members = [...]``) or ACL ``entity``."""
    found: list[str] = []
    for attr in ("member", "members", "entity", "role_entity"):
        value = _attr_value(_top_level(body), attr) or ""
        found += [m for m in _PUBLIC_MEMBERS if f'"{m}"' in value or f':{m}"' in value]
    return sorted(set(found))


def _set_true_re(name: str) -> re.Pattern[str]:
    pattern = _TRUE_RE_CACHE.get(name)
    if pattern is None:
        pattern = _TRUE_RE_CACHE[name] = re.compile(rf"^[ \t]*{re.escape(name)}[ \t]*=[ \t]*true\b", re.MULTILINE)
    return pattern


# Host paths whose mount hands a container the node (kubernetes provider pods).
_SENSITIVE_HOST_PATHS = (
    "/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd", "/run/containerd",
    "/var/run/crio", "/var/lib/kubelet", "/etc", "/root", "/proc", "/sys", "/dev", "/boot",
)
_HOST_PATH_RE = re.compile(r"\bhost_path\s*\{")
_HOST_PATH_PATH_RE = re.compile(r'^[ \t]*path[ \t]*=[ \t]*"([^"\n]*)"', re.MULTILINE)
_K8S_BLOCK_SCAN_LIMIT = 2000
_TF_K8S_WORKLOADS = frozenset(
    f"kubernetes_{kind}{suffix}"
    for kind in ("pod", "deployment", "daemonset", "daemon_set", "stateful_set", "job", "cron_job", "replication_controller", "replica_set")
    for suffix in ("", "_v1")
)
_TF_K8S_ROLES = frozenset({"kubernetes_cluster_role", "kubernetes_cluster_role_v1", "kubernetes_role", "kubernetes_role_v1"})
_TF_K8S_BINDINGS = frozenset({
    "kubernetes_cluster_role_binding", "kubernetes_cluster_role_binding_v1",
    "kubernetes_role_binding", "kubernetes_role_binding_v1",
})
_TF_K8S_SERVICES = frozenset({"kubernetes_service", "kubernetes_service_v1"})
_BROAD_K8S_GROUPS = frozenset({"system:authenticated", "system:unauthenticated", "system:anonymous"})


# `aws_lb.x.arn`, `aws_lb.x[0].arn`, `aws_lb.x["a"].arn`
_LB_REF_RE = re.compile(r'^aws_(?:lb|alb)\.([\w-]+)(?:\[[^\]\n]{0,64}\])?\.(?:arn|id)$')


_V2_API_REF_RE = re.compile(r'^aws_apigatewayv2_api\.([\w-]+)(?:\[[^\]\n]{0,64}\])?\.id$')
_ACTION_TYPE_RE = re.compile(r"[\w-]{1,64}")


def _action_type(block: str) -> str:
    """Lower-cased literal `type` of a `default_action` (or the `content` of
    a `dynamic "default_action"`), or ``?`` when it is computed."""
    content = _sub_blocks(block, "content")
    raw = _extract_attr(content[0] if content else block, "type")
    if raw is None:
        return "?" if content or "for_each" in block else ""
    value = raw.strip()
    if not _ACTION_TYPE_RE.fullmatch(value):
        return "?"
    return value.lower()


# Read-only system data under the sensitive trees: CA bundles, TLS certs,
# time zone, the syslog socket, GPUs. Same list as attackmap-analyzer-iac.
_BENIGN_HOST_PATHS = (
    "/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/localtime", "/etc/timezone", "/etc/machine-id",
    "/etc/os-release", "/etc/letsencrypt", "/dev/log", "/dev/dri", "/usr/share/ca-certificates",
)

# Kubernetes RBAC: same rules as attackmap-analyzer-iac (records.py).
_SENSITIVE_API_GROUPS = frozenset({
    "", "*", "apps", "batch", "extensions", "policy", "networking.k8s.io", "rbac.authorization.k8s.io",
    "admissionregistration.k8s.io", "certificates.k8s.io", "apiextensions.k8s.io",
})
_SENSITIVE_RESOURCES = frozenset({
    "*", "secrets", "pods", "pods/exec", "pods/attach", "pods/ephemeralcontainers", "deployments", "daemonsets",
    "statefulsets", "replicasets", "jobs", "cronjobs", "replicationcontrollers", "serviceaccounts",
    "serviceaccounts/token", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "nodes",
    "nodes/proxy", "persistentvolumes", "mutatingwebhookconfigurations", "validatingwebhookconfigurations",
    "customresourcedefinitions", "certificatesigningrequests", "certificatesigningrequests/approval",
    "configmaps", "namespaces", "networkpolicies",
})
_ADMIN_LIKE_ROLES = frozenset({"cluster-admin", "admin", "edit"})
_INTERNAL_LB_ANNOTATIONS = {
    "aws-load-balancer-internal": {"true", "0.0.0.0/0"},
    "aws-load-balancer-scheme": {"internal"},
    "azure-load-balancer-internal": {"true"},
    "oci-load-balancer-internal": {"true"},
    "openstack-internal-load-balancer": {"true"},
    "load-balancer-type": {"internal"},
    "ibm-load-balancer-cloud-provider-ip-type": {"private"},
    "alibaba-cloud-loadbalancer-address-type": {"intranet"},
}
_ANNOTATION_PAIR_RE = re.compile(r'"([^"\n]{1,253})"[ \t]*[=:][ \t]*("[^"\n]{0,253}"|[^\s,}]{1,253})')


def _rbac_wildcard(groups: set[str] | None, verbs: set[str], resources: set[str]) -> bool:
    """A `*` on a control-plane API group, for every resource or a sensitive
    one (not `verbs = ["*"]` on `events` or `metrics.k8s.io`)."""
    if "*" not in verbs and "*" not in resources:
        return False
    if groups is not None and not groups & _SENSITIVE_API_GROUPS:
        return False
    return "*" in resources or bool(resources & _SENSITIVE_RESOURCES)


def _internal_lb(annotations: str) -> bool:
    """A cloud's internal-LB annotation set to an internal value (an explicit
    `"false"` / `internet-facing` is external; a computed value counts as
    internal, i.e. not reported)."""
    for key, raw in _ANNOTATION_PAIR_RE.findall(annotations):
        accepted = _INTERNAL_LB_ANNOTATIONS.get(key.rsplit("/", 1)[-1].lower())
        if accepted is None:
            continue
        value = raw.strip().strip('"').lower()
        if not raw.startswith('"') and value not in {"true", "false"}:
            return True  # var.x / local.y
        if value in accepted or "${" in value:
            return True
    return False


def _host_path_severity(path: str) -> str:
    normalized = posixpath.normpath(path) if path else path
    if any(normalized == p or normalized.startswith(p + "/") for p in _BENIGN_HOST_PATHS):
        return "low"
    if normalized == "/" or any(normalized == p or normalized.startswith(p + "/") for p in _SENSITIVE_HOST_PATHS):
        return "high"
    return "low"


def _string_list(value: str | None) -> list[str]:
    return re.findall(r'"([^"\n]*)"', value or "")


# ---------- Route auth (AttackMap#256) ----------

REQUIRED, ANONYMOUS, UNKNOWN = "required", "anonymous", "unknown"
# API Gateway / Lambda URL authorization values that authenticate the caller.
_APIGW_GUARDS = frozenset({"AWS_IAM", "COGNITO_USER_POOLS", "CUSTOM", "JWT"})
_APIGW_ROOT_REF = re.compile(r"^aws_api_gateway_rest_api\.[\w-]+\.root_resource_id$")
_APIGW_RESOURCE_REF = re.compile(r"^aws_api_gateway_resource\.([\w-]+)\.id$")
_APIGW_PATH_DEPTH = 32
_APIGW_PATH_PART = re.compile(r"^[\w.~+{}-]+$")
_TF_REFERENCE = re.compile(r"^(?:var|local|module|data|each|count|aws_\w+)\.")


def _attr_line(body: str, name: str) -> str | None:
    """The source text of a top-level ``name = ...`` attribute line."""
    match = re.search(rf"^[ \t]*{re.escape(name)}[ \t]*=[^\n]*", _top_level(body), re.MULTILINE)
    return " ".join(match.group(0).split()) if match else None


def _route_auth(body: str, attr: str, extra_guards: tuple[str, ...] = ()) -> tuple[str, list[str], str | None]:
    """``(auth, guards, evidence)`` from an ``authorization`` /
    ``authorization_type`` attribute. ``NONE`` written out is explicitly
    public; an absent or computed value (``var.x``) is unknown."""
    value = (_extract_attr(body, attr) or "").strip()
    evidence = _attr_line(body, attr)
    guards: list[str] = []
    lines: list[str] = []
    if value.upper() in _APIGW_GUARDS:
        authorizer = _extract_attr(body, "authorizer_id")
        guards.append(value.upper() + (f" ({authorizer})" if authorizer else ""))
        lines += [line for line in (evidence, _attr_line(body, "authorizer_id")) if line]
    for name in extra_guards:
        if (_extract_attr(body, name) or "").lower() == "true":
            guards.append(name)
            lines += [line for line in (_attr_line(body, name),) if line]
    if guards:
        return REQUIRED, guards, "; ".join(lines) or None
    if value.upper() == "NONE" and evidence:
        return ANONYMOUS, [], evidence
    return UNKNOWN, [], None


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
        # REST API (v1) methods become routes after the walk, once every
        # aws_api_gateway_resource (path_part / parent_id) has been seen.
        self._apigw_resources: dict[str, tuple[str, str]] = {}
        self._apigw_methods: list[tuple[str, str, tuple[str, list[str], str | None], str, int]] = []
        # HTTP listeners are judged after the walk, once every aws_lb's
        # `internal` flag has been seen.
        # (module directory, aws_lb name) -> internal? (None: computed value)
        self._lb_internal: dict[tuple[str, str], bool | None] = {}
        self._http_listeners: list[tuple[str, str, str, int, str, str, str | None]] = []
        # API Gateway v2 `$default` routes, judged once every API's protocol is known.
        self._v2_protocols: dict[tuple[str, str], str | None] = {}
        self._v2_default_routes: list[tuple[str, str, str, str, int, str | None]] = []
        # Context of the resource being dispatched: for_each/count and, for a
        # file inside a local module, the module blocks that call it.
        self._context: str | None = None
        self._body_line: int | None = None

        files: list[tuple[Path, str, str]] = []
        for file_path in iter_repo_files(root, suffixes=_WALK_SUFFIXES, skip_dirs=SKIP_DIRS):
            if not _is_terraform_file(file_path):
                continue
            content = read_source(file_path)
            if content is None:
                continue
            files.append((file_path, rel(file_path, root), content))
        self._module_callers = self._collect_module_callers(files)

        for file_path, relative, content in files:
            result.files_scanned += 1
            if "hcl" not in result.languages:
                result.languages.append("hcl")

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

        self._emit_http_listeners(result)
        self._emit_v2_default_routes(result)
        for resource_ref, http_method, auth, file, line in self._apigw_methods:
            path = self._apigw_path(resource_ref)
            if path is not None:
                self._append_unique_route(
                    result, path, http_method, file, line,
                    auth=auth[0], guards=auth[1], guard_evidence=auth[2],
                )

        result.languages.sort()
        _SEEN.pop(id(result), None)
        return result

    def _apigw_path(self, resource_ref: str) -> str | None:
        """Full path of a REST API resource reference, or None when a parent
        isn't a literal resource in this repo."""
        parts: list[str] = []
        ref = resource_ref.strip()
        for _ in range(_APIGW_PATH_DEPTH):
            if _APIGW_ROOT_REF.match(ref):
                return "/" + "/".join(reversed(parts))
            match = _APIGW_RESOURCE_REF.match(ref)
            resource = self._apigw_resources.get(match.group(1)) if match else None
            if resource is None:
                return None
            parent, path_part = resource
            if not _APIGW_PATH_PART.match(path_part) or _TF_REFERENCE.match(path_part):
                return None  # interpolated or computed
            parts.append(path_part)
            ref = parent.strip()
        return None

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
        for match, body in _top_blocks(RESOURCE_BLOCK_PATTERN, content):
            resource_type, resource_name = match.group(1), match.group(2)
            line = line_of(content, match.start())
            self._dispatch_with_context(
                resource_type, resource_name, body, relative, line,
                _line_snippet(content, match.start()), result, body_line=line,
            )

    def _dispatch_with_context(
        self, resource_type: str, resource_name: str, body: str, file: str, line: int, ev: str,
        result: ScanResult, *, body_line: int | None,
    ) -> None:
        """Dispatch one resource with its instancing and module context set.
        ``for_each`` / ``count`` is also appended to the hint evidence, since
        one open security group may be N instances. ``body_line`` is the
        source line the body starts on (None for ``.tf.json``)."""
        instancing = _instancing(body)
        self._context = self._resource_context(file, instancing)
        self._body_line = body_line
        try:
            self._dispatch_resource(
                resource_type, resource_name, body, file, line,
                f"{ev} [{instancing}]" if instancing else ev, result,
            )
        finally:
            self._context = None
            self._body_line = None

    def _resource_context(self, file: str, instancing: str | None) -> str | None:
        parts = [instancing] if instancing else []
        callers = self._module_callers.get(_file_dir(file), [])
        if callers:
            more = f" +{len(callers) - 2} more" if len(callers) > 2 else ""
            parts.append("in local module called as " + ", ".join(callers[:2]) + more)
        return "; ".join(parts) or None

    def _attr_lineno(self, body: str, name: str, default: int) -> int:
        """Source line of the first ``name = ...`` in ``body`` (at any depth),
        or ``default`` (the block header) when unknown."""
        if self._body_line is None:
            return default
        match = re.search(rf"^[ \t]*{re.escape(name)}[ \t]*=", body, re.MULTILINE)
        return self._body_line + body.count("\n", 0, match.start()) if match else default

    def _extract_variables(self, content: str, relative: str, result: ScanResult) -> None:
        for match, body in _top_blocks(VARIABLE_BLOCK_PATTERN, content):
            self._handle_variable(
                match.group(1), body, relative,
                line_of(content, match.start()),
                _line_snippet(content, match.start()),
                result,
            )

    def _extract_modules(self, content: str, relative: str, result: ScanResult) -> None:
        for match, body in _top_blocks(MODULE_BLOCK_PATTERN, content):
            self._handle_module(
                match.group(1), body, relative, line_of(content, match.start()), result, body_line=line_of(content, match.start()),
            )

    @staticmethod
    def _collect_module_callers(files: list[tuple[Path, str, str]]) -> dict[str, list[str]]:
        """Directory of each local module (``source = "./modules/x"``) →
        ``module.<name> (<caller file>:<line>)`` for every block calling it,
        so resources found in that directory are attributed to their caller."""
        callers: dict[str, list[str]] = {}
        seen: set[tuple[str, str]] = set()
        for file_path, relative, content in files:
            if file_path.suffix != ".tf":
                continue
            for match, body in _top_blocks(MODULE_BLOCK_PATTERN, content):
                target = _local_module_dir(relative, _extract_attr(body, "source") or "")
                if target is None:
                    continue
                label = f"module.{match.group(1)} ({relative}:{line_of(content, match.start())})"
                bucket = callers.setdefault(target, [])
                if (target, label) not in seen:
                    seen.add((target, label))
                    bucket.append(label)
        return callers

    def _handle_module(
        self, name: str, body: str, file: str, line: int, result: ScanResult, *, body_line: int | None,
    ) -> None:
        self._append_unique_service(result, f"module:{name}", file)
        source = _extract_attr(body, "source")
        if not source:
            return
        problem = _module_pin_problem(source, _extract_attr(body, "version"))
        if problem is None:
            return
        severity, reason, confidence = problem
        self._body_line = body_line
        try:
            source_line = self._attr_lineno(body, "source", line)
        finally:
            self._body_line = None
        self._append_misconfig(
            result, "iac_module_unpinned", f"module.{name}", "terraform", file, source_line,
            f"{_attr_line(body, 'source')} ({reason})",
            severity=severity, confidence=confidence, escalation=_MODULE_ESCALATION,
            context=_instancing(body),
        )

    def _extract_data_sources(self, content: str, relative: str, result: ScanResult) -> None:
        for match, body in _top_blocks(DATA_BLOCK_PATTERN, content):
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
                                    self._dispatch_with_context(
                                        block_type, block_name, body, relative, line, ev, result, body_line=None,
                                    )
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
        locator.find("module", from_start=True)
        for module_obj in _json_objects(document.get("module")):
            for module_name, raw_body in module_obj.items():
                offset = locator.find(module_name)
                for body_obj in _json_objects(raw_body) or [{}]:
                    self._handle_module(
                        module_name, _json_to_hcl(body_obj), relative, line_of(content, offset), result, body_line=None,
                    )

    # ---------- Block handlers (shared by HCL and JSON syntax) ----------

    def _handle_provider(self, provider: str, file: str, line: int, ev: str, result: ScanResult) -> None:
        label = _PROVIDER_LABEL.get(provider, f"terraform-{provider}")
        self._append_unique_framework(result, label, file, line, ev)

    def _handle_variable(self, var_name: str, body: str, file: str, line: int, ev: str, result: ScanResult) -> None:
        sensitive = (_extract_attr(body, "sensitive") or "").lower() == "true"
        if not (sensitive or _looks_secret_shaped(var_name)):
            return
        # A literal string `default` on a secret variable is a credential
        # committed to the repo (#4); a bare declaration only names one.
        default = _VARIABLE_STRING_DEFAULT_RE.search(_top_level(body))
        if default and _credential_shaped_default(var_name, default.group(1)) and (
            sensitive or _tfvars_key_is_secret(var_name)
        ):
            self._append_unique_secret(
                result, var_name, file, line,
                # Never echo the literal itself into the report.
                f'variable "{var_name}" {{ default = "<redacted>" }}',
                kind="hardcoded",
            )
            return
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
        self._misconfig_checks(resource_type, resource_name, body, file, line, result)
        resource = f"{resource_type}.{resource_name}"
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
            if authorization_type == "NONE":
                self._append_misconfig(
                    result, "public_invoker", resource, "aws", file, self._attr_lineno(body, "authorization_type", line),
                    'authorization_type = "NONE"', severity="low", confidence=0.85,
                    escalation="anyone on the internet can invoke the function; its own code is the only access control",
                )
            # A function URL serves every method and path of the function.
            auth, guards, evidence = _route_auth(body, "authorization_type")
            self._append_unique_route(
                result, "/", "ANY", file, line, auth=auth, guards=guards, guard_evidence=evidence,
            )
            return
        if resource_type == "aws_api_gateway_resource":
            parent = _extract_attr(body, "parent_id") or ""
            self._apigw_resources.setdefault(resource_name, (parent, _extract_attr(body, "path_part") or ""))
            return
        if resource_type == "aws_api_gateway_method":
            http_method = (_extract_attr(body, "http_method") or "ANY").upper()
            authorization = (_extract_attr(body, "authorization") or "").upper()
            if authorization == "NONE":
                self._append_unique_entrypoint(
                    result, f"apigw_open_method:{http_method}:{resource_name}", file, line, ev,
                )
                # CORS preflight (OPTIONS) is unauthenticated by design; an
                # API key is a (weak) caller check.
                if http_method != "OPTIONS" and not _is_true(body, "api_key_required"):
                    self._append_misconfig(
                        result, "api_no_authorizer", resource, "aws", file, self._attr_lineno(body, "authorization", line),
                        f'{http_method} method with authorization = "NONE" and no API key', severity="medium", confidence=0.8,
                        escalation="anyone on the internet can call the integration behind this method",
                    )
            else:
                self._append_unique_entrypoint(
                    result, f"apigw_method:{http_method}:{resource_name}", file, line, ev,
                )
            resource_id = _extract_attr(body, "resource_id")
            if resource_id:
                auth = _route_auth(body, "authorization", ("api_key_required",))
                self._apigw_methods.append((resource_id, http_method, auth, file, line))
            return
        if resource_type == "aws_apigatewayv2_route":
            route_key = _extract_attr(body, "route_key") or ""
            authorization_type = (_extract_attr(body, "authorization_type") or "").upper()
            if route_key.strip() == "$default":
                # The catch-all route: on an HTTP API it serves every method
                # and path no other route matches. A WebSocket API has a
                # `$default` too, which can't take an authorizer, so the API's
                # protocol is resolved after the walk.
                self._v2_default_routes.append(
                    (resource, _extract_attr(body, "api_id") or "", body, file, line, self._context)
                )
                return
            if route_key:
                # route_key is "GET /users" or "POST /things" — split into method + path.
                parts = route_key.strip().split(maxsplit=1)
                if len(parts) == 2:
                    method, path = parts[0].upper(), parts[1]
                    auth, guards, evidence = _route_auth(body, "authorization_type")
                    self._append_unique_route(
                        result, path, method, file, line,
                        auth=auth, guards=guards, guard_evidence=evidence,
                    )
                    if authorization_type == "NONE":
                        self._append_unique_entrypoint(
                            result, f"apigwv2_open:{resource_name}", file, line, ev,
                        )
                    # HTTP API routes default to authorization_type NONE.
                    raw_auth = _extract_attr(body, "authorization_type")
                    if method != "OPTIONS" and (authorization_type == "NONE" or raw_auth is None):
                        self._append_misconfig(
                            result, "api_no_authorizer", resource, "aws", file,
                            self._attr_lineno(body, "authorization_type" if raw_auth else "route_key", line),
                            f'route "{route_key}" with '
                            + ('authorization_type = "NONE"' if raw_auth else "no authorization_type (defaults to NONE)"),
                            severity="medium", confidence=0.85 if raw_auth else 0.7,
                            escalation="anyone on the internet can call the integration behind this route",
                        )
            return
        if resource_type == "aws_apigatewayv2_api":
            protocol = (_extract_attr(body, "protocol_type") or "").strip().upper()
            self._v2_protocols[(_file_dir(file), resource_name)] = protocol if protocol in {"HTTP", "WEBSOCKET"} else None
        if resource_type in {"aws_lb", "aws_alb"}:
            internal = (_extract_attr(body, "internal") or "false").strip().lower()
            self._lb_internal[(_file_dir(file), resource_name)] = (
                True if internal == "true" else False if internal == "false" else None
            )
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
                self._s3_public_acl(result, resource, body, file, line, acl)
            if _scan_json_policies(_attr_value(body, "policy") or "").public_principal:
                self._append_unique_entrypoint(
                    result, f"s3_public_policy:{resource_name}", file, line, ev,
                )
                self._s3_public_policy(result, resource, body, file, line)
            return
        if resource_type == "aws_s3_bucket_policy":
            if _scan_json_policies(body).public_principal:
                self._append_unique_entrypoint(
                    result, f"s3_public_policy:{resource_name}", file, line, ev,
                )
                self._s3_public_policy(result, resource, body, file, line)
            return
        if resource_type == "aws_s3_bucket_acl":
            acl = (_extract_attr(body, "acl") or "").lower()
            if acl in _PUBLIC_S3_ACLS:
                self._append_unique_entrypoint(
                    result, f"s3_public_acl:{resource_name}", file, line, ev,
                )
                self._s3_public_acl(result, resource, body, file, line, acl)
            return
        if resource_type == "aws_s3_bucket_public_access_block":
            for attr in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                value = (_extract_attr(body, attr) or "true").lower()
                if value == "false":
                    self._append_unique_entrypoint(
                        result, f"s3_public_block_disabled:{resource_name}", file, line, ev,
                    )
                    self._append_misconfig(
                        result, "public_data_access", resource, "aws", file, self._attr_lineno(body, attr, line),
                        f"{attr} = false", severity="low", confidence=0.7,
                        escalation="the bucket's public-access guard is off, so a public ACL or policy takes effect",
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
                self._append_misconfig(
                    result, "public_network_access", resource, "aws", file, self._attr_lineno(body, "publicly_accessible", line),
                    "publicly_accessible = true", severity="medium", confidence=0.85,
                    escalation="the database gets a public DNS name and address; only its security groups and password protect it",
                )
            self._check_rds_encryption(result, resource_type, resource, body, file, line)
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

    # ---------- Misconfiguration checks (#4) ----------

    def _misconfig_checks(
        self, resource_type: str, name: str, body: str, file: str, line: int, result: ScanResult,
    ) -> None:
        """Resource types whose only output is a `CloudMisconfig`. Checks on
        types the dispatcher already handles live in its branches."""
        resource = f"{resource_type}.{name}"
        platform = _platform(resource_type)

        def emit(kind: str, attr: str, evidence: str, *, at: int | None = None, **kw: object) -> None:
            # `at`: offset in `body` of the specific block (one hostPath of
            # several), else the line of the first `attr = ...`.
            if at is not None and at >= 0 and self._body_line is not None:
                where = self._body_line + body.count("\n", 0, at)
            else:
                where = self._attr_lineno(body, attr, line)
            self._append_misconfig(result, kind, resource, platform, file, where, evidence, **kw)  # type: ignore[arg-type]

        # ---- AWS ----
        if resource_type in {"aws_instance", "aws_launch_configuration"}:
            if _is_true(body, "associate_public_ip_address"):
                emit(
                    "public_network_access", "associate_public_ip_address", "associate_public_ip_address = true",
                    severity="low", confidence=0.8,
                    escalation="the instance gets a public IPv4 address, reachable wherever its security groups allow",
                )
            return
        if resource_type == "aws_launch_template":
            if any(_is_true(ni, "associate_public_ip_address") for ni in _sub_blocks(body, "network_interfaces")):
                emit(
                    "public_network_access", "associate_public_ip_address", "network_interfaces { associate_public_ip_address = true }",
                    severity="low", confidence=0.8,
                    escalation="every instance launched from it gets a public IPv4 address",
                )
            return
        if resource_type == "aws_eks_cluster":
            self._check_eks_endpoint(body, emit)
            return
        if resource_type in {"aws_lb_listener", "aws_alb_listener"}:
            protocol = (_extract_attr(body, "protocol") or "").upper()
            if protocol != "HTTP":
                return
            actions = [_action_type(a) for a in _sub_blocks(body, "default_action")]
            if "redirect" in actions or "?" in actions:
                return  # redirects, or a computed type that may be one
            lb_ref = _extract_attr(body, "load_balancer_arn") or ""
            self._http_listeners.append(
                (resource, lb_ref, file, self._attr_lineno(body, "protocol", line), _attr_line(body, "protocol") or 'protocol = "HTTP"',
                 "fixed-response" if actions and all(a == "fixed-response" for a in actions) else "forward", self._context),
            )
            return
        if resource_type in {"aws_elasticsearch_domain", "aws_opensearch_domain"}:
            if _scan_json_policies(_attr_value(body, "access_policies") or "").public_principal:
                in_vpc = bool(_sub_blocks(body, "vpc_options"))
                emit(
                    "public_data_access", "access_policies", 'access_policies allow Principal "*" with no Condition',
                    severity="medium" if in_vpc else "high", confidence=0.85,
                    escalation="anyone who can reach the domain endpoint can read and write its indices"
                    + (" (endpoint is inside a VPC)" if in_vpc else ""),
                )
            return
        if resource_type in {"aws_elasticsearch_domain_policy", "aws_opensearch_domain_policy"}:
            if _scan_json_policies(body).public_principal:
                emit(
                    "public_data_access", "access_policies", 'access_policies allow Principal "*" with no Condition',
                    severity="medium", confidence=0.8,
                    escalation="anyone who can reach the domain endpoint can read and write its indices",
                )
            return

        # ---- GCP ----
        if resource_type.startswith(("google_cloud_run_service_iam_", "google_cloud_run_v2_service_iam_",
                                     "google_cloudfunctions_function_iam_", "google_cloudfunctions2_function_iam_")):
            members = _public_members(body)
            if members and not resource_type.endswith("_policy"):
                emit(
                    "public_invoker", "member" if _extract_attr(body, "member") else "members",
                    f"{_attr_line(body, 'role') or 'role'} granted to {', '.join(members)}",
                    severity="low", confidence=0.85,
                    escalation="anyone on the internet can invoke the service; its own code is the only access control",
                )
            return
        if resource_type.startswith(("google_storage_bucket_iam_", "google_storage_bucket_access_control",
                                     "google_storage_default_object_access_control", "google_storage_object_access_control",
                                     "google_storage_bucket_acl")):
            members = _public_members(body)
            predefined = (_extract_attr(body, "predefined_acl") or "").lower()
            if predefined in {"publicread", "publicreadwrite"}:
                members.append(f"predefined_acl {predefined}")
            if not members or resource_type.endswith("_policy"):
                return
            role = (_extract_attr(body, "role") or "") + " " + (_attr_value(_top_level(body), "role_entity") or "")
            writable = any(w in role.lower() for w in ("admin", "writer", "creator", "owner")) or predefined == "publicreadwrite"
            emit(
                "public_data_access", "role", f"{_attr_line(body, 'role') or resource_type} granted to {', '.join(members)}",
                severity="high" if writable else "medium", confidence=0.9,
                escalation="anyone on the internet can " + ("modify" if writable else "read") + " the bucket's objects",
            )
            return

        # ---- Azure ----
        if resource_type.startswith("azurerm_"):
            if _is_true(body, "public_network_access_enabled"):
                emit(
                    "public_network_access", "public_network_access_enabled", "public_network_access_enabled = true",
                    severity="medium", confidence=0.85,
                    escalation="the service endpoint accepts connections from any network; only its own auth protects it",
                )
            if resource_type == "azurerm_storage_account" and _is_true(body, "allow_nested_items_to_be_public"):
                emit(
                    "public_data_access", "allow_nested_items_to_be_public", "allow_nested_items_to_be_public = true",
                    severity="medium", confidence=0.8,
                    escalation="containers in the account can be made publicly readable without further review",
                )
            if resource_type == "azurerm_storage_container":
                access = (_extract_attr(body, "container_access_type") or "").lower()
                if access in {"blob", "container"}:
                    emit(
                        "public_data_access", "container_access_type", f'container_access_type = "{access}"',
                        severity="high" if access == "container" else "medium", confidence=0.9,
                        escalation="anonymous clients can read its blobs" + (" and list them" if access == "container" else ""),
                    )
            return

        # ---- Kubernetes provider ----
        if resource_type in _TF_K8S_WORKLOADS:
            self._check_k8s_workload(body, emit)
        elif resource_type in _TF_K8S_ROLES:
            self._check_k8s_role(resource_type, body, emit)
        elif resource_type in _TF_K8S_BINDINGS:
            self._check_k8s_binding(body, emit)
        elif resource_type in _TF_K8S_SERVICES:
            spec = next(iter(_sub_blocks(body, "spec")), "")
            svc_type = _extract_attr(spec, "type") or ""
            if svc_type in {"LoadBalancer", "NodePort"} and _attr_value(_top_level(spec), "load_balancer_source_ranges") is None:
                annotations = _attr_value(next(iter(_sub_blocks(body, "metadata")), ""), "annotations") or ""
                if not _internal_lb(annotations):
                    emit(
                        "exposed_service", "type", f'type = "{svc_type}" with no load_balancer_source_ranges',
                        severity="low", confidence=0.7,
                        escalation="the service is reachable from outside the cluster by any source address",
                    )

    @staticmethod
    def _check_eks_endpoint(body: str, emit) -> None:  # type: ignore[no-untyped-def]
        """EKS: `endpoint_public_access` defaults to true and
        `public_access_cidrs` to 0.0.0.0/0. Only literal (or defaulted)
        values are judged; a variable is not."""
        vpc = next(iter(_sub_blocks(body, "vpc_config")), None)
        if vpc is None:
            return
        public = _extract_attr(vpc, "endpoint_public_access")
        if public is not None and public.strip().lower() != "true":
            return  # false, or computed
        cidrs = _attr_value(_top_level(vpc), "public_access_cidrs")
        if cidrs is not None and not _has_open_cidr(cidrs):
            return  # restricted, or computed
        defaulted = [n for n, v in (("endpoint_public_access", public), ("public_access_cidrs", cidrs)) if v is None]
        evidence = (
            f"{_attr_line(vpc, 'endpoint_public_access') or 'endpoint_public_access not set (defaults to true)'}; "
            f"{_attr_line(vpc, 'public_access_cidrs') or 'public_access_cidrs not set (defaults to 0.0.0.0/0)'}"
        )
        emit(
            "public_cluster_endpoint", "endpoint_public_access" if public is not None else "vpc_config", evidence,
            severity="medium", confidence=0.6 if defaulted else 0.9,
            escalation="the Kubernetes API server is reachable from the internet; a leaked kubeconfig or token, or an API server bug, is enough to get in",
        )

    @staticmethod
    def _check_k8s_workload(body: str, emit) -> None:  # type: ignore[no-untyped-def]
        """kubernetes provider pods / pod templates (snake_case fields)."""
        if _set_true_re("privileged").search(body):
            emit("privileged_container", "privileged", "privileged = true", severity="high", confidence=0.9,
                 escalation="a privileged container has every device and capability of the node: root on the host")
        if _set_true_re("allow_privilege_escalation").search(body):
            emit("privilege_escalation_allowed", "allow_privilege_escalation", "allow_privilege_escalation = true",
                 severity="medium", confidence=0.9, escalation="setuid binaries in the image can raise the process to root")
        for attr, severity in (("host_pid", "high"), ("host_network", "medium"), ("host_ipc", "medium")):
            if _set_true_re(attr).search(body):
                emit("host_namespace_shared", attr, f"{attr} = true", severity=severity, confidence=0.9,
                     escalation=f"the pod shares the node's {attr.removeprefix('host_').upper()} namespace")
        for match in _HOST_PATH_RE.finditer(body):
            window = body[match.end(): match.end() + _K8S_BLOCK_SCAN_LIMIT]
            inner, _ = _block_body(window, 0)
            path = _HOST_PATH_PATH_RE.search(inner)
            if path is None:
                continue
            value = path.group(1)
            severity = _host_path_severity(value)
            emit("host_path_mount", "path", f'host_path {{ path = "{value}" }}', at=match.end() + path.start(), severity=severity,
                 confidence=0.9 if severity == "high" else 0.6,
                 escalation="host filesystem access from the pod" + (": node root / container runtime control" if severity == "high" else ""))

    @staticmethod
    def _check_k8s_role(resource_type: str, body: str, emit) -> None:  # type: ignore[no-untyped-def]
        cluster = "cluster_role" in resource_type
        for rule in _sub_blocks(body, "rule"):
            top = _top_level(rule)
            verbs = {v.lower() for v in _string_list(_attr_value(top, "verbs"))}
            resources = {r.lower() for r in _string_list(_attr_value(top, "resources"))}
            groups_value = _attr_value(top, "api_groups")
            groups = None if groups_value is None else set(_string_list(groups_value))
            if _rbac_wildcard(groups, verbs, resources):
                emit("rbac_wildcard", "verbs", at=body.find(rule), evidence=f"rule verbs={sorted(verbs)} resources={sorted(resources)}",
                     severity="high" if cluster else "medium", confidence=0.9,
                     escalation="the role grants every verb or resource, including secrets and RBAC objects")
                continue
            escalating = sorted(verbs & {"escalate", "bind", "impersonate"})
            if escalating or ({"pods/exec", "pods/attach"} & resources and "create" in verbs):
                emit("rbac_escalation", "verbs", at=body.find(rule), evidence=f"rule verbs={sorted(verbs)} resources={sorted(resources)}",
                     severity="high", confidence=0.85,
                     escalation="a subject bound to this role can grant itself more permissions or run commands in other pods")
            elif "secrets" in resources and verbs & {"get", "list", "watch"} and not _string_list(
                _attr_value(top, "resource_names")
            ):  # resource_names narrows it to named Secrets
                emit("rbac_secret_access", "verbs", at=body.find(rule), evidence=f"rule verbs={sorted(verbs)} resources=[secrets]",
                     severity="medium" if cluster else "low", confidence=0.8,
                     escalation="a subject bound to this role can read Secret values (service-account tokens, credentials)")

    @staticmethod
    def _check_k8s_binding(body: str, emit) -> None:  # type: ignore[no-untyped-def]
        role_ref = next(iter(_sub_blocks(body, "role_ref")), "")
        role = _extract_attr(role_ref, "name") or ""
        subjects = [(_extract_attr(s, "kind") or "", _extract_attr(s, "name") or "") for s in _sub_blocks(body, "subject")]
        broad = [name for _, name in subjects if name in _BROAD_K8S_GROUPS]
        # system:authenticated bound to system:basic-user and the like is the
        # default; only an admin-like role makes it a takeover.
        if role == "cluster-admin" or (broad and role in _ADMIN_LIKE_ROLES):
            who = ", ".join(f"{k}/{n}" for k, n in subjects) or "subjects"
            emit("cluster_admin_binding", "name", f"role_ref {role or '?'} bound to {who}", severity="high", confidence=0.9,
                 escalation="every bound subject (and any pod running as it) has full control of the cluster")

    def _emit_v2_default_routes(self, result: ScanResult) -> None:
        for resource, api_ref, body, file, line, context in self._v2_default_routes:
            match = _V2_API_REF_RE.match(api_ref.strip())
            if match is None or self._v2_protocols.get((_file_dir(file), match.group(1))) != "HTTP":
                continue  # WebSocket API, or an API we can't resolve
            auth, guards, evidence = _route_auth(body, "authorization_type")
            self._append_unique_route(
                result, "/{proxy+}", "ANY", file, line, auth=auth, guards=guards, guard_evidence=evidence,
            )
            raw_auth = _extract_attr(body, "authorization_type")
            if raw_auth is None or raw_auth.strip().upper() == "NONE":
                self._body_line = None
                self._append_misconfig(
                    result, "api_no_authorizer", resource, "aws", file, line,
                    "catch-all $default route with "
                    + ('authorization_type = "NONE"' if raw_auth else "no authorization_type (defaults to NONE)"),
                    severity="medium", confidence=0.85 if raw_auth else 0.7,
                    escalation="every method and path no other route matches reaches the default integration unauthenticated",
                    context=context,
                )

    def _emit_http_listeners(self, result: ScanResult) -> None:
        for resource, lb_ref, file, line, evidence, action, context in self._http_listeners:
            match = _LB_REF_RE.match(lb_ref.strip())
            internal = self._lb_internal.get((_file_dir(file), match.group(1))) if match else False
            if internal is not False:
                continue  # internal, or `internal` is computed
            self._append_misconfig(
                result, "plaintext_listener", resource, "aws", file, line,
                f"{evidence} with no redirect to HTTPS",
                severity="low" if action == "fixed-response" else "medium",
                # A load balancer we couldn't resolve (var./module output) may be internal.
                confidence=0.8 if match else 0.6,
                escalation="traffic (cookies, tokens, form posts) crosses the network in clear text",
                context=context,
            )

    def _s3_public_acl(self, result: ScanResult, resource: str, body: str, file: str, line: int, acl: str) -> None:
        writable = acl == "public-read-write"
        self._append_misconfig(
            result, "public_data_access", resource, "aws", file, self._attr_lineno(body, "acl", line),
            f'acl = "{acl}"', severity="high" if writable else "medium", confidence=0.9,
            escalation="anyone on the internet can " + ("list and overwrite" if writable else "list and read") + " the bucket",
        )

    def _s3_public_policy(self, result: ScanResult, resource: str, body: str, file: str, line: int) -> None:
        self._append_misconfig(
            result, "public_data_access", resource, "aws", file, self._attr_lineno(body, "policy", line),
            'bucket policy allows Principal "*" with no Condition', severity="medium", confidence=0.85,
            escalation="anyone on the internet gets the actions the statement allows on the bucket",
        )

    def _check_rds_encryption(
        self, result: ScanResult, resource_type: str, resource: str, body: str, file: str, line: int,
    ) -> None:
        """``storage_encrypted`` defaults to false on ``aws_db_instance``.
        Replicas and snapshot restores inherit their source's encryption, and
        a ``kms_key_id`` implies encryption, so those are left alone."""
        value = _extract_attr(body, "storage_encrypted")
        if _is_literal_false(value):
            self._append_misconfig(
                result, "unencrypted_storage", resource, "aws", file, self._attr_lineno(body, "storage_encrypted", line),
                "storage_encrypted = false", severity="medium", confidence=0.9,
                escalation="snapshots, backups and the underlying volumes hold the data in clear text",
            )
            return
        if (
            value is None
            and resource_type == "aws_db_instance"
            and not any(_extract_attr(body, a) for a in ("replicate_source_db", "snapshot_identifier", "kms_key_id"))
        ):
            self._append_misconfig(
                result, "unencrypted_storage", resource, "aws", file, line,
                "storage_encrypted not set (defaults to false)", severity="low", confidence=0.6,
                escalation="snapshots, backups and the underlying volumes hold the data in clear text",
            )

    def _append_misconfig(
        self,
        result: ScanResult,
        kind: str,
        resource: str,
        platform: str,
        file: str,
        line: int | None,
        evidence: str,
        *,
        severity: str,
        confidence: float = 0.8,
        escalation: str | None = None,
        context: str | None = None,
    ) -> None:
        """One `CloudMisconfig` per (kind, file, line, resource). ``context``
        defaults to the dispatched resource's for_each/count and module."""
        if not _CLOUD_RECORDS:
            return  # AttackMap core older than the CloudMisconfig contract
        if not _first_seen(result, ("misconfig", kind, file, line, resource, evidence)):
            return
        result.cloud_misconfigs.append(
            CloudMisconfig(
                kind=kind, file=file, line=line, resource=resource, platform=platform,
                context=context if context is not None else self._context,
                escalation_path=escalation, evidence_text=evidence,
                severity=severity, confidence=confidence,
            )
        )

    # ---------- Append helpers ----------

    @staticmethod
    def _append_unique_route(
        result: ScanResult,
        path: str,
        method: str,
        file: str,
        line: int | None,
        *,
        auth: str = UNKNOWN,
        guards: list[str] | None = None,
        guard_evidence: str | None = None,
    ) -> None:
        # Route.auth / guards / guard_evidence (AttackMap#256): core trusts
        # them over its own resolution; an older core ignores the fields. The
        # apigw*_open / lambda_url_open entrypoint hints stay for one release.
        key = (path, method, file)
        if not _first_seen(result, ("routes", *key)):
            return
        result.routes.append(
            Route(
                path=path, method=method, file=file, line=line,
                auth=auth, guards=list(guards or []), guard_evidence=guard_evidence,
            )
        )

    @staticmethod
    def _append_unique_database(result: ScanResult, kind: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (kind, file)
        if not _first_seen(result, ("databases", *key)):
            return
        result.databases.append(DatabaseHint(kind=kind, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_auth(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None, confidence: float) -> None:
        key = (hint, file)
        if not _first_seen(result, ("auth_hints", *key)):
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
        if not _first_seen(result, ("secret_hints", *key)):
            return
        extra = {"kind": kind} if kind is not None else {}
        result.secret_hints.append(
            SecretHint(name=name, file=file, line=line, evidence_text=evidence, confidence=0.85, **extra)
        )

    @staticmethod
    def _append_unique_external(result: ScanResult, target: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (target, file)
        if not _first_seen(result, ("external_calls", *key)):
            return
        result.external_calls.append(ExternalCall(target=target, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_framework(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if not _first_seen(result, ("framework_hints", *key)):
            return
        result.framework_hints.append(FrameworkHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_entrypoint(result: ScanResult, hint: str, file: str, line: int | None, evidence: str | None) -> None:
        key = (hint, file)
        if not _first_seen(result, ("entrypoint_hints", *key)):
            return
        result.entrypoint_hints.append(EntrypointHint(hint=hint, file=file, line=line, evidence_text=evidence))

    @staticmethod
    def _append_unique_service(result: ScanResult, hint: str, file: str) -> None:
        key = (hint, file)
        if not _first_seen(result, ("service_hints", *key)):
            return
        result.service_hints.append(ServiceHint(hint=hint, file=file))


__all__ = ["TerraformAnalyzer"]
