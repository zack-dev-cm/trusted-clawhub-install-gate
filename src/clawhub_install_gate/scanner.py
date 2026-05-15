from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Iterable

from .models import Finding, InspectReport
from .policy import classify_verdict


TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}
KNOWN_BINARY_ASSET_SUFFIXES = {
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".webp",
}
ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".dmg",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
MAX_TEXT_BYTES = 1_000_000
SEVERITY_ORDER = {"BLOCK": 0, "WARNING": 1, "INFO": 2}
DYNAMIC_CODE_MESSAGE = "Dynamic code execution requires manual review."
JS_IDENTIFIER_RE = r"[A-Za-z_$][A-Za-z0-9_$]*"
JS_SPACE_RE = r"(?:\s|/\*[\s\S]*?\*/)*"
JS_REQUIRED_SPACE_RE = r"(?:\s|/\*[\s\S]*?\*/)+"
JS_GLOBAL_RE = r"(?:window|globalThis|self|global)"
JS_STRING_QUOTE_RE = r"['\"`]"
JS_OBJECT_ACCESS_RE = (
    rf"(?:{JS_SPACE_RE}(?:(?:\?\.|\.){JS_SPACE_RE}{JS_IDENTIFIER_RE}|"
    rf"\[{JS_SPACE_RE}(?:\d+|{JS_STRING_QUOTE_RE}{JS_IDENTIFIER_RE}{JS_STRING_QUOTE_RE}){JS_SPACE_RE}\]))"
)
JS_OBJECT_RE = (
    rf"(?:{JS_IDENTIFIER_RE}(?:{JS_OBJECT_ACCESS_RE})*|"
    rf"\({JS_SPACE_RE}{JS_IDENTIFIER_RE}{JS_SPACE_RE}\)(?:{JS_OBJECT_ACCESS_RE})*)"
)
JS_WS_MEMBER_ACCESS_RE = (
    rf"{JS_OBJECT_RE}{JS_SPACE_RE}(?:(?:\?\.|\.){JS_SPACE_RE}WebSocket\b|"
    rf"(?:\?\.{JS_SPACE_RE})?\[{JS_SPACE_RE}{JS_STRING_QUOTE_RE}WebSocket{JS_STRING_QUOTE_RE}{JS_SPACE_RE}\])"
)
JS_WS_GLOBAL_ACCESS_RE = (
    rf"(?:{JS_GLOBAL_RE}{JS_SPACE_RE}(?:(?:\?\.|\.){JS_SPACE_RE}WebSocket|"
    rf"(?:\?\.{JS_SPACE_RE})?\[{JS_SPACE_RE}{JS_STRING_QUOTE_RE}WebSocket{JS_STRING_QUOTE_RE}{JS_SPACE_RE}\])|"
    rf"\({JS_SPACE_RE}{JS_GLOBAL_RE}{JS_SPACE_RE}\){JS_SPACE_RE}"
    rf"(?:\.{JS_SPACE_RE}WebSocket|\[{JS_SPACE_RE}{JS_STRING_QUOTE_RE}WebSocket{JS_STRING_QUOTE_RE}{JS_SPACE_RE}\]))"
)
JS_WS_REFLECT_GET_RE = (
    rf"Reflect\.get{JS_SPACE_RE}\({JS_SPACE_RE}(?:{JS_GLOBAL_RE}|\({JS_SPACE_RE}{JS_GLOBAL_RE}{JS_SPACE_RE}\))"
    rf"{JS_SPACE_RE},{JS_SPACE_RE}{JS_STRING_QUOTE_RE}WebSocket{JS_STRING_QUOTE_RE}{JS_SPACE_RE}\)"
)
JS_WS_REFERENCE_RE = (
    rf"(?:\({JS_SPACE_RE})*(?:WebSocket\b|{JS_WS_GLOBAL_ACCESS_RE}|{JS_WS_MEMBER_ACCESS_RE})"
    rf"{JS_SPACE_RE}(?:\){JS_SPACE_RE})*"
)
JS_WS_BIND_RE = (
    rf"{JS_WS_REFERENCE_RE}{JS_SPACE_RE}(?:"
    rf"(?:\.|\?\.){JS_SPACE_RE}bind|"
    rf"\[{JS_SPACE_RE}{JS_STRING_QUOTE_RE}bind{JS_STRING_QUOTE_RE}{JS_SPACE_RE}\]"
    rf"){JS_SPACE_RE}\("
)
DYNAMIC_COMPILE_CALL_RE = re.compile(
    rf"(?<![A-Za-z0-9_$])(?:(?P<receiver>{JS_IDENTIFIER_RE}(?:\.{JS_IDENTIFIER_RE})*)\.)?\$?compile\s*\("
)
MULTILINE_WS_IMPORT_RE = re.compile(
    r"\bimport\s*\{[^};]{0,500}\bWebSocket\b[^};]{0,500}\}\s*from\s*['\"]ws['\"]",
    re.IGNORECASE,
)
MULTILINE_WEBSOCKET_PACKAGE_IMPORT_RE = re.compile(
    r"\bimport\s*\{[^};]{0,500}\}\s*from\s*['\"]websocket['\"]",
    re.IGNORECASE,
)
MULTILINE_WS_DEFAULT_IMPORT_RE = re.compile(
    rf"\bimport{JS_REQUIRED_SPACE_RE}{JS_IDENTIFIER_RE}"
    rf"(?:{JS_SPACE_RE},{JS_SPACE_RE}\{{[^;]{{0,500}}?\}})?"
    rf"{JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"](?:ws|websocket)['\"]",
    re.IGNORECASE,
)
MULTILINE_WS_NAMESPACE_IMPORT_RE = re.compile(
    rf"\bimport{JS_REQUIRED_SPACE_RE}\*{JS_REQUIRED_SPACE_RE}as{JS_REQUIRED_SPACE_RE}{JS_IDENTIFIER_RE}"
    rf"{JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"](?:ws|websocket)['\"]",
    re.IGNORECASE,
)
MULTILINE_WS_DYNAMIC_IMPORT_RE = re.compile(
    rf"\bimport{JS_SPACE_RE}\({JS_SPACE_RE}['\"](?:ws|websocket)['\"]{JS_SPACE_RE}\)",
    re.IGNORECASE,
)
MULTILINE_WS_REQUIRE_RE = re.compile(
    rf"\brequire{JS_SPACE_RE}\({JS_SPACE_RE}['\"](?:ws|websocket)['\"]{JS_SPACE_RE}\)",
    re.IGNORECASE,
)
MULTILINE_WS_EXPORT_RE = re.compile(
    r"\bexport\b[^;]{0,500}\bfrom\s*['\"](?:ws|websocket)['\"]",
    re.IGNORECASE,
)
MULTILINE_WS_ANY_IMPORT_RE = re.compile(
    rf"\bimport(?:{JS_REQUIRED_SPACE_RE}type)?{JS_REQUIRED_SPACE_RE}(?:"
    rf"\{{[^;]{{0,500}}\bWebSocket\b[^;]{{0,500}}\}}|"
    rf"{JS_IDENTIFIER_RE}{JS_SPACE_RE},{JS_SPACE_RE}\{{[^;]{{0,500}}\bWebSocket\b[^;]{{0,500}}\}}|"
    rf"WebSocket\b(?:{JS_SPACE_RE},{JS_SPACE_RE}\{{[^;]{{0,500}}\}})?"
    rf"){JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
MULTILINE_WS_CONSTRUCTOR_RE = re.compile(rf"\bnew{JS_SPACE_RE}{JS_WS_REFERENCE_RE}\(", re.IGNORECASE)
MULTILINE_WS_REFLECT_CONSTRUCT_RE = re.compile(
    rf"\bReflect\.construct{JS_SPACE_RE}\({JS_SPACE_RE}{JS_WS_REFERENCE_RE}",
    re.IGNORECASE,
)
MULTILINE_WS_WRAPPED_REFERENCE_RE = re.compile(
    rf"\[{JS_SPACE_RE}{JS_WS_REFERENCE_RE}{JS_SPACE_RE}\](?:{JS_SPACE_RE}\[{JS_SPACE_RE}\d+{JS_SPACE_RE}\])?",
    re.IGNORECASE,
)
MULTILINE_WS_BIND_RE = re.compile(JS_WS_BIND_RE, re.IGNORECASE)
MULTILINE_WS_DESTRUCTURED_ALIAS_RE = re.compile(
    rf"(?:\b(?:const|let|var)\s*)?\(?\s*\{{[\s\S]{{0,500}}?\bWebSocket\b(?:\s*:\s*{JS_IDENTIFIER_RE})?"
    rf"[\s\S]{{0,500}}?\}}\s*=\s*(?:{JS_GLOBAL_RE}|{JS_OBJECT_RE})\b",
    re.IGNORECASE,
)
MULTILINE_WS_ALIAS_RE = re.compile(
    rf"\b(?:(?:const|let|var)\s+)?{JS_IDENTIFIER_RE}\s*="
    rf"\s*(?:{JS_WS_REFERENCE_RE}|{JS_WS_MEMBER_ACCESS_RE}|{JS_WS_REFLECT_GET_RE})",
    re.IGNORECASE,
)
MULTILINE_WS_EXTENDS_RE = re.compile(
    rf"\bclass(?:\s+{JS_IDENTIFIER_RE})?\s+extends{JS_SPACE_RE}(?:{JS_WS_REFERENCE_RE}|{JS_WS_MEMBER_ACCESS_RE})",
    re.IGNORECASE,
)
MULTILINE_PY_WEBSOCKET_IMPORT_RE = re.compile(
    r"\bfrom\s+websocket\s+import\s*(?:"
    r"\([^)]{0,500}(?:\b(?:create_connection|WebSocket(?:App)?)\b|\*)[^)]{0,500}\)|"
    r"\\\s*\n\s*(?:create_connection|WebSocket(?:App)?|\*)\b"
    r")",
    re.IGNORECASE,
)


class InspectError(RuntimeError):
    """Raised when a target cannot be inspected."""


class InstallTargetNotSupported(InspectError):
    """Raised when the input is not a local unpacked skill directory."""


class PolicyError(RuntimeError):
    """Raised when policy blocks installation."""


class Rule:
    def __init__(self, code: str, severity: str, pattern: re.Pattern[str], message: str) -> None:
        self.code = code
        self.severity = severity
        self.pattern = pattern
        self.message = message


SECRET_RULES = (
    Rule(
        "private-key-block",
        "BLOCK",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "Private key material appears in the skill.",
    ),
    Rule(
        "github-token",
        "BLOCK",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "GitHub token-like value appears in the skill.",
    ),
    Rule(
        "github-fine-grained-token",
        "BLOCK",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "GitHub fine-grained token-like value appears in the skill.",
    ),
    Rule(
        "api-key",
        "BLOCK",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "API key-like value appears in the skill.",
    ),
    Rule(
        "aws-access-key",
        "BLOCK",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS access key-like value appears in the skill.",
    ),
)

BLOCK_RULES = (
    Rule(
        "credential-exfiltration",
        "BLOCK",
        re.compile(
            r"\b(send|upload|post|transmit|exfiltrat\w*)\b.{0,100}"
            r"\b(secret|token|api[_ -]?key|credential|password|cookie|\.env|ssh|keychain)\b",
            re.IGNORECASE,
        ),
        "Instruction appears to transmit credentials or secrets.",
    ),
    Rule(
        "credential-harvest",
        "BLOCK",
        re.compile(
            r"\b(read|collect|scan|dump|steal|harvest)\b.{0,100}"
            r"(~/(?:\.ssh|\.aws|\.gnupg)|id_rsa|keychain|cookies?|\.env|tokens?)",
            re.IGNORECASE,
        ),
        "Instruction appears to collect local credentials or secret stores.",
    ),
    Rule(
        "prompt-override",
        "BLOCK",
        re.compile(
            r"(?<!to )\bignore\s+(?:all\s+)?(?:previous\s+)?"
            r"(?:system|developer|safety|policy|instructions)\b|"
            r"\b(?:override|bypass|disable)\s+(?:the\s+)?"
            r"(?:system|developer|safety|approval|policy|instructions)\b",
            re.IGNORECASE,
        ),
        "Skill text attempts to override higher-priority instructions or safety rules.",
    ),
    Rule(
        "destructive-shell",
        "BLOCK",
        re.compile(
            r"(rm\s+-rf\s+(?:/|\$HOME|~)|mkfs\s|dd\s+if=.*\s+of=/dev/|"
            r":\(\)\s*\{\s*:\|:|chmod\s+-R\s+777\s+(?:/|\$HOME|~))",
            re.IGNORECASE,
        ),
        "Destructive shell behavior appears in the skill.",
    ),
    Rule(
        "curl-pipe-shell",
        "BLOCK",
        re.compile(r"\b(curl|wget)\b[^\n|;]*[|;]\s*(?:sudo\s+)?(?:sh|bash)\b", re.IGNORECASE),
        "Remote download is piped directly into a shell.",
    ),
    Rule(
        "security-weakening",
        "BLOCK",
        re.compile(
            r"\b(disable|bypass|weaken|turn off)\b.{0,80}"
            r"\b(auto[-_ ]?review|sandbox|approval|firewall|gatekeeper|selinux|sip|policy)\b|"
            r"\b(git\s+config\s+--global\s+http\.sslVerify\s+false|"
            r"spctl\s+--master-disable|csrutil\s+disable|setenforce\s+0|ufw\s+disable)\b",
            re.IGNORECASE,
        ),
        "Instruction appears to weaken approval, sandbox, or host security controls.",
    ),
    Rule(
        "denial-circumvention",
        "BLOCK",
        re.compile(
            r"\b(work ?around|route around|circumvent|retry indirectly)\b.{0,100}"
            r"\b(denial|blocked|auto[-_ ]?review|approval|policy)\b",
            re.IGNORECASE,
        ),
        "Instruction appears to route around an approval or auto-review denial.",
    ),
)

WARNING_RULES = (
    Rule(
        "network-client",
        "WARNING",
        re.compile(
            r"\b(?:requests|httpx|socket)\.[A-Za-z_]\w*|"
            r"\burllib\.request\b|"
            r"\b(?:XMLHttpRequest|curl|wget)\b|"
            r"\bimport\s+websocket\b|"
            r"\b__import__\(\s*['\"]websocket['\"]\s*\)|"
            r"\bfrom\s+websocket\s+import\s+\*|"
            r"\bfrom\s+websocket\s+import\s+[^\n;]*\b(?:create_connection|WebSocket(?:App)?)\b|"
            r"\bimport\s+websocket\s+as\s+[A-Za-z_]\w*\b|"
            r"\bwebsocket\.(?:create_connection|WebSocket(?:App)?)\b|"
            rf"\b(?:fetch|WebSocket){JS_SPACE_RE}\(|"
            rf"(?:\(|,){JS_SPACE_RE}{JS_WS_REFERENCE_RE}{JS_SPACE_RE}(?:,|\))|"
            rf"\bnew{JS_SPACE_RE}{JS_WS_REFERENCE_RE}\(|"
            rf"{JS_WS_BIND_RE}|"
            rf"\bReflect\.construct{JS_SPACE_RE}\({JS_SPACE_RE}{JS_WS_REFERENCE_RE}|"
            rf"\[{JS_SPACE_RE}{JS_WS_REFERENCE_RE}{JS_SPACE_RE}\](?:{JS_SPACE_RE}\[{JS_SPACE_RE}\d+{JS_SPACE_RE}\])?|"
            r"(?:\b(?:const|let|var)\s*)?\(?\s*\{[^\n;]*\bWebSocket\b(?:\s*:\s*[A-Za-z_$][A-Za-z0-9_$]*)?"
            rf"[^\n;]*\}}\s*=\s*(?:{JS_GLOBAL_RE}|{JS_OBJECT_RE})\b|"
            rf"\b(?:(?:const|let|var)\s+)?{JS_IDENTIFIER_RE}\s*="
            rf"\s*(?:{JS_WS_REFERENCE_RE}|{JS_WS_MEMBER_ACCESS_RE}|{JS_WS_REFLECT_GET_RE})|"
            rf"\bclass(?:\s+{JS_IDENTIFIER_RE})?\s+extends{JS_SPACE_RE}(?:{JS_WS_REFERENCE_RE}|{JS_WS_MEMBER_ACCESS_RE})|"
            rf"{JS_WS_REFLECT_GET_RE}|"
            rf"{JS_WS_GLOBAL_ACCESS_RE}|"
            r"\brequire\s*\(\s*['\"]ws['\"]\s*\)(?:\.WebSocket)?|"
            r"\brequire\s*\(\s*['\"]websocket['\"]\s*\)(?:\.[A-Za-z_]\w*)?|"
            rf"\bimport{JS_SPACE_RE}\({JS_SPACE_RE}['\"](?:ws|websocket)['\"]{JS_SPACE_RE}\)|"
            rf"\bimport{JS_REQUIRED_SPACE_RE}\*{JS_REQUIRED_SPACE_RE}as{JS_REQUIRED_SPACE_RE}{JS_IDENTIFIER_RE}"
            rf"{JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"](?:ws|websocket)['\"]|"
            rf"\bimport{JS_REQUIRED_SPACE_RE}{JS_IDENTIFIER_RE}(?:{JS_SPACE_RE},[^\n;]*)?"
            rf"{JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"](?:ws|websocket)['\"]|"
            rf"\bimport(?:{JS_REQUIRED_SPACE_RE}type)?{JS_REQUIRED_SPACE_RE}(?:"
            rf"\{{[^\n;]*\bWebSocket\b[^\n;]*\}}|"
            rf"{JS_IDENTIFIER_RE}{JS_SPACE_RE},{JS_SPACE_RE}\{{[^\n;]*\bWebSocket\b[^\n;]*\}}|"
            rf"WebSocket\b(?:{JS_SPACE_RE},[^\n;]*)?"
            rf"){JS_REQUIRED_SPACE_RE}from{JS_SPACE_RE}['\"][^'\"]+['\"]|"
            r"\bimport\b[^\n;]*\bWebSocket\b[^\n;]*\bfrom\s*['\"]ws['\"]|"
            r"\bimport\b[^\n;]*\bfrom\s*['\"]websocket['\"]|"
            r"\bexport\b[^\n;]*\bfrom\s*['\"](?:ws|websocket)['\"]",
            re.IGNORECASE,
        ),
        "Network-capable code or command requires manual review.",
    ),
    Rule(
        "shell-execution",
        "WARNING",
        re.compile(
            r"\b(subprocess\.(run|Popen|call)|os\.system|child_process|"
            r"shell=True|bash\s+-c|sh\s+-c)\b",
            re.IGNORECASE,
        ),
        "Shell or subprocess execution requires manual review.",
    ),
    Rule(
        "dynamic-code-execution",
        "WARNING",
        re.compile(
            r"\b(?:eval|exec)\s*\(|"
            r"\bnew\s+Function\s*\(|"
            r"\b(?:pickle|marshal)\.loads\b"
        ),
        DYNAMIC_CODE_MESSAGE,
    ),
    Rule(
        "environment-access",
        "WARNING",
        re.compile(r"\b(os\.environ|process\.env|getenv\(|load_dotenv|\.env)\b"),
        "Environment or .env access requires manual review.",
    ),
    Rule(
        "package-install",
        "WARNING",
        re.compile(r"\b(pip install|npm install|pnpm add|yarn add|brew install|apt-get install)\b"),
        "Installer command requires dependency and network review.",
    ),
    Rule(
        "base64-decode",
        "WARNING",
        re.compile(r"\b(base64\s+-d|base64\.b64decode|Buffer\.from\([^)]*,\s*['\"]base64['\"])\b"),
        "Encoded payload handling requires manual review.",
    ),
    Rule(
        "absolute-home-path",
        "WARNING",
        re.compile(r"(~/(?:\.ssh|\.aws|\.config|\.gnupg)|/(?:Users|home)/[A-Za-z0-9._-]+)"),
        "Home-directory or private workstation path requires manual review.",
    ),
    Rule(
        "overclaimed-safety",
        "WARNING",
        re.compile(r"\b(guaranteed safe|provably safe|proof of safety|cannot be unsafe)\b", re.IGNORECASE),
        "Safety claim is too absolute for static review.",
    ),
)


def resolve_local_skill_target(target: str) -> Path:
    candidate = Path(target).expanduser()
    if not candidate.exists():
        if "://" in target or "/" not in target:
            raise InstallTargetNotSupported(
                "Only local unpacked skill directories are supported in v0.1."
            )
        raise InspectError(f"Target does not exist: {candidate}")
    return candidate.resolve()


def inspect_target(target: str) -> InspectReport:
    root = resolve_local_skill_target(target)
    findings = audit_skill(root)
    verdict = classify_verdict(findings)
    skill_name = extract_skill_name(root) or root.name
    return InspectReport(
        root=str(root),
        skill_name=skill_name,
        verdict=verdict,
        findings=findings,
        file_count=count_files(root),
        content_sha256=compute_manifest_sha256(root),
    )


def audit_skill(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not root.exists():
        return [Finding("BLOCK", "missing-skill", str(root), None, "Skill path does not exist.")]
    if not root.is_dir():
        return [Finding("BLOCK", "not-directory", str(root), None, "Skill path is not a directory.")]

    skill_md = root / "SKILL.md"
    if not skill_md.exists():
        findings.append(Finding("BLOCK", "missing-skill-md", "SKILL.md", None, "Missing required SKILL.md."))
    else:
        text = read_text(skill_md)
        if text is None:
            findings.append(
                Finding("BLOCK", "unreadable-skill-md", "SKILL.md", None, "SKILL.md is not UTF-8 text.")
            )
        else:
            findings.extend(audit_skill_md(root, text))

    local_python_modules = collect_local_python_modules(root)
    for path in iter_skill_files(root):
        rel_path = path.relative_to(root).as_posix()
        findings.extend(audit_file_metadata(root, path, rel_path))
        if path.is_symlink():
            continue
        text = read_text(path)
        if text is None:
            findings.extend(audit_binary_file(path, rel_path))
            continue
        findings.extend(audit_text_file(rel_path, text, local_python_modules=local_python_modules))
        findings.extend(audit_dependency_file(rel_path, text))

    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.path, item.code))


def iter_skill_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.is_file() or path.is_symlink():
            yield path


def collect_local_python_modules(root: Path) -> set[str]:
    modules: set[str] = set()
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.is_dir() and (path / "__init__.py").exists():
            modules.add(path.name)
        elif path.suffix == ".py":
            modules.add(path.stem)
    return modules


def audit_file_metadata(root: Path, path: Path, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    name = path.name
    suffix = path.suffix.lower()

    if path.is_symlink():
        try:
            target = path.resolve()
            target.relative_to(root)
            message = "Symlink requires manual review even though it resolves inside the skill."
            severity = "WARNING"
            code = "symlink"
        except ValueError:
            message = "Symlink resolves outside the skill directory."
            severity = "BLOCK"
            code = "escaping-symlink"
        findings.append(Finding(severity, code, rel_path, None, message))
        return findings

    if name.startswith(".env") and name not in {".env.example", ".env.sample", ".env.template"}:
        findings.append(Finding("BLOCK", "tracked-env-file", rel_path, None, "Tracked .env file is present."))
    if suffix in {".key", ".pem", ".p12", ".pfx"} or name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        findings.append(Finding("BLOCK", "credential-file", rel_path, None, "Credential or key-like file is present."))
    if suffix in ARCHIVE_SUFFIXES:
        findings.append(
            Finding(
                "BLOCK",
                "archive-payload",
                rel_path,
                None,
                "Archive payload must be unpacked and audited before install.",
            )
        )

    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > MAX_TEXT_BYTES:
        findings.append(
            Finding("WARNING", "large-file", rel_path, None, "Large file requires manual review for hidden payloads.")
        )
    if os.access(path, os.X_OK) and suffix not in {".py", ".sh", ".js", ".mjs", ".ts"}:
        findings.append(
            Finding("WARNING", "unexpected-executable", rel_path, None, "Executable bit is set on an unusual file type.")
        )

    return findings


def audit_binary_file(path: Path, rel_path: str) -> list[Finding]:
    suffix = path.suffix.lower()
    if os.access(path, os.X_OK):
        return [Finding("BLOCK", "binary-executable", rel_path, None, "Executable binary or unreadable executable is present.")]
    if suffix in KNOWN_BINARY_ASSET_SUFFIXES:
        return [Finding("INFO", "binary-asset", rel_path, None, "Known binary asset is present.")]
    if suffix not in TEXT_SUFFIXES:
        return [Finding("WARNING", "unknown-binary", rel_path, None, "Unreadable or unknown binary file requires review.")]
    return []


def audit_skill_md(root: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return [Finding("BLOCK", "missing-frontmatter", "SKILL.md", 1, "SKILL.md must start with YAML frontmatter.")]

    end = None
    for index, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            end = index
            break
    if end is None:
        return [Finding("BLOCK", "unterminated-frontmatter", "SKILL.md", 1, "SKILL.md frontmatter is not closed.")]

    fields: dict[str, str] = {}
    current_key: str | None = None
    for line_number, raw_line in enumerate(lines[1 : end - 1], start=2):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line.startswith((" ", "\t")) and current_key:
            fields[current_key] = f"{fields[current_key]} {stripped.removeprefix('-').strip()}".strip()
            continue
        if ":" not in stripped:
            findings.append(
                Finding("BLOCK", "invalid-frontmatter-line", "SKILL.md", line_number, "Frontmatter line is not key: value.")
            )
            continue
        key, value = stripped.split(":", 1)
        current_key = key.strip()
        fields[current_key] = value.strip().strip("'\"")

    missing = {"name", "description"} - fields.keys()
    for field in sorted(missing):
        findings.append(Finding("BLOCK", "missing-frontmatter-field", "SKILL.md", None, f"Missing frontmatter field: {field}."))

    extra = sorted(set(fields) - {"name", "description"})
    for field in extra:
        findings.append(Finding("INFO", "extra-frontmatter-field", "SKILL.md", None, f"Extra frontmatter field: {field}."))

    skill_name = fields.get("name", "")
    if skill_name and skill_name != root.name:
        findings.append(Finding("INFO", "name-folder-mismatch", "SKILL.md", None, "Skill name does not match the folder name."))
    if any("TODO" in value or "Complete" in value for value in fields.values()):
        findings.append(Finding("BLOCK", "template-frontmatter", "SKILL.md", None, "Template placeholder remains in frontmatter."))
    if len(fields.get("description", "")) < 80:
        findings.append(Finding("WARNING", "thin-description", "SKILL.md", None, "Description is too thin to support safe triggering."))

    return findings


def audit_text_file(rel_path: str, text: str, *, local_python_modules: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if "TODO:" in text or "[TODO" in text:
        findings.append(Finding("WARNING", "template-marker", rel_path, None, "Template TODO marker remains in the skill."))

    findings.extend(audit_multiline_network_clients(rel_path, text))
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in (*SECRET_RULES, *BLOCK_RULES, *WARNING_RULES):
            if rule.pattern.search(line):
                if rule in SECRET_RULES and looks_like_placeholder(line):
                    continue
                findings.append(Finding(rule.severity, rule.code, rel_path, line_number, rule.message))
    findings.extend(audit_dynamic_compile_calls(rel_path, text, local_python_modules=local_python_modules or set()))
    return findings


def audit_multiline_network_clients(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in (
        MULTILINE_WS_IMPORT_RE,
        MULTILINE_WEBSOCKET_PACKAGE_IMPORT_RE,
        MULTILINE_WS_DEFAULT_IMPORT_RE,
        MULTILINE_WS_NAMESPACE_IMPORT_RE,
        MULTILINE_WS_DYNAMIC_IMPORT_RE,
        MULTILINE_WS_REQUIRE_RE,
        MULTILINE_WS_EXPORT_RE,
        MULTILINE_WS_ANY_IMPORT_RE,
        MULTILINE_WS_CONSTRUCTOR_RE,
        MULTILINE_WS_REFLECT_CONSTRUCT_RE,
        MULTILINE_WS_WRAPPED_REFERENCE_RE,
        MULTILINE_WS_BIND_RE,
        MULTILINE_WS_DESTRUCTURED_ALIAS_RE,
        MULTILINE_WS_ALIAS_RE,
        MULTILINE_WS_EXTENDS_RE,
        MULTILINE_PY_WEBSOCKET_IMPORT_RE,
    ):
        for match in pattern.finditer(text):
            if "\n" not in match.group(0):
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    "WARNING",
                    "network-client",
                    rel_path,
                    line_number,
                    "Network-capable code or command requires manual review.",
                )
            )
    return findings


def has_spaced_receiver_dot(text: str, index: int) -> bool:
    i = index - 1
    while i >= 0 and text[i] in " \t\f\v":
        i -= 1
    return i >= 0 and text[i] == "."


def audit_dynamic_compile_calls(rel_path: str, text: str, *, local_python_modules: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_python_file = Path(rel_path).suffix in {".py", ".pyi"}
    line_number = 1
    line_scan_offset = 0
    for match in DYNAMIC_COMPILE_CALL_RE.finditer(text):
        open_paren = text.find("(", match.start(), match.end())
        args_text = extract_call_args(text, open_paren)
        line_number += text.count("\n", line_scan_offset, match.start())
        line_scan_offset = match.start()
        if args_text is None:
            findings.append(Finding("WARNING", "dynamic-code-execution", rel_path, line_number, DYNAMIC_CODE_MESSAGE))
            break
        args = split_top_level_args(args_text)
        receiver = match.group("receiver")
        effective_safe_regex_receivers: set[str] = set()
        if is_python_file:
            shadow_text = text[: match.start()]
            call_line_start = text.rfind("\n", 0, match.start()) + 1
            call_line_prefix = text[call_line_start : match.start()]
            call_indent = len(call_line_prefix) - len(call_line_prefix.lstrip(" \t"))
            effective_safe_regex_receivers = infer_regex_compile_receivers(
                shadow_text,
                local_python_modules,
                call_indent=call_indent,
            )
            if receiver in effective_safe_regex_receivers and (
                regex_receiver_is_shadowed(receiver, shadow_text, call_indent=call_indent)
                or receiver_is_bound_later_in_comprehension(receiver, text, match.start())
                or receiver_is_rebound_later_in_enclosing_scope(receiver, text, match.start(), call_indent)
            ):
                effective_safe_regex_receivers.remove(receiver)
        unmatched_receiver = match.start() > 0 and has_spaced_receiver_dot(text, match.start())
        if unmatched_receiver or is_dynamic_compile_call(
            is_python_file,
            effective_safe_regex_receivers,
            receiver,
            args,
            args_text,
        ):
            findings.append(Finding("WARNING", "dynamic-code-execution", rel_path, line_number, DYNAMIC_CODE_MESSAGE))
    return findings


def infer_regex_compile_receivers(text: str, local_python_modules: set[str], *, call_indent: int) -> set[str]:
    receivers: set[str] = set()
    lines = text.splitlines()
    scope_body_start = python_current_scope_body_start(lines, call_indent)
    for index, line in enumerate(lines):
        code_part = line.partition("#")[0]
        if not code_part.strip():
            continue
        indent = len(code_part) - len(code_part.lstrip(" \t"))
        in_current_scope = index >= scope_body_start
        if (in_current_scope and indent > call_indent) or (not in_current_scope and indent >= call_indent):
            continue
        code = code_part.strip()
        if not code.startswith("import "):
            continue
        prefix_text = "\n".join(lines[:index])
        for imported in code.removeprefix("import ").split(","):
            parts = imported.strip().split()
            if not parts or parts[0] not in {"re", "regex"} or parts[0] in local_python_modules:
                continue
            if python_sys_modules_spoofs_module(prefix_text, {parts[0]}):
                continue
            receiver = parts[2] if len(parts) >= 3 and parts[1] == "as" else parts[0]
            receivers.add(receiver)

    return receivers


def regex_receiver_is_shadowed(receiver: str, text: str, *, call_indent: int) -> bool:
    escaped = re.escape(receiver)
    scoped_text = python_shadow_text_for_call_scope(text, call_indent)
    code_lines = [line.strip() for line in scoped_text.splitlines()]
    if python_receiver_is_shadowed_by_ast(receiver, text, call_indent=call_indent):
        return True
    if python_sys_modules_spoofs_module(scoped_text, {"re", "regex"}):
        return True
    if regex_receiver_alias_compile_is_mutated(receiver, scoped_text):
        return True
    if re.search(rf"(?m)(?:^|[;:])\s*{escaped}\s*(?::[^=\n]+)?=", scoped_text):
        return True
    if re.search(rf"(?m)(?:^|[;:(,])\s*{escaped}\s*:=", scoped_text):
        return True
    if re.search(rf"\b(?:globals|locals)\s*\(\s*\)\s*\[\s*['\"]{escaped}['\"]\s*\]\s*=", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*\)\s*\[\s*['\"]{escaped}['\"]\s*\]\s*=", scoped_text):
        return True
    if re.search(rf"\b(?:globals|locals)\s*\(\s*\)\s*\.\s*__setitem__\s*\(\s*['\"]{escaped}['\"]\s*,", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*\)\s*\.\s*__setitem__\s*\(\s*['\"]{escaped}['\"]\s*,", scoped_text):
        return True
    if re.search(rf"\b(?:globals|locals)\s*\(\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}\b{escaped}\s*=", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}\b{escaped}\s*=", scoped_text):
        return True
    if re.search(rf"\b(?:globals|locals)\s*\(\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]{escaped}['\"]\s*:", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]{escaped}['\"]\s*:", scoped_text):
        return True
    if re.search(rf"(?m)(?:^|[;:])\s*{escaped}\s*\.\s*compile\s*=", scoped_text):
        return True
    if re.search(rf"\b{escaped}\s*\.\s*__setattr__\s*\(\s*['\"]compile['\"]\s*,", scoped_text):
        return True
    if re.search(rf"\b(?:{JS_IDENTIFIER_RE}\.)?__setattr__\s*\(\s*{escaped}\s*,\s*['\"]compile['\"]\s*,", scoped_text):
        return True
    if re.search(rf"\b(?:{JS_IDENTIFIER_RE}\.)?setattr\s*\(\s*{escaped}\s*,\s*['\"]compile['\"]\s*,", scoped_text):
        return True
    if re.search(rf"{escaped}\s*\.\s*__dict__\s*\[\s*['\"]compile['\"]\s*\]\s*=", scoped_text):
        return True
    if re.search(rf"{escaped}\s*\.\s*__dict__\s*\.\s*__setitem__\s*\(\s*['\"]compile['\"]\s*,", scoped_text):
        return True
    if re.search(rf"{escaped}\s*\.\s*__dict__\s*\.\s*update\s*\([\s\S]{{0,500}}\bcompile\s*=", scoped_text):
        return True
    if re.search(rf"{escaped}\s*\.\s*__dict__\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]compile['\"]\s*:", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*{escaped}\s*\)\s*\[\s*['\"]compile['\"]\s*\]\s*=", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*{escaped}\s*\)\s*\.\s*__setitem__\s*\(\s*['\"]compile['\"]\s*,", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*{escaped}\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}\bcompile\s*=", scoped_text):
        return True
    if re.search(rf"\bvars\s*\(\s*{escaped}\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]compile['\"]\s*:", scoped_text):
        return True
    if receiver_is_bound_as_function_argument(receiver, scoped_text, call_indent):
        return True
    if receiver_is_bound_as_lambda_argument(receiver, scoped_text, call_indent):
        return True
    if re.search(rf"(?m)\bfor\s+[^\n:]*\b{escaped}\b[^\n:]*\bin\b", scoped_text):
        return True
    if re.search(rf"(?m)\b(?:with|except)\b[^\n:]*\bas\s+{escaped}\b", scoped_text):
        return True
    if re.search(rf"(?m)\bcase\b[^\n]*\b{escaped}\b[^\n]*:", scoped_text):
        return True
    if from_import_shadows_receiver(receiver, scoped_text):
        return True

    for code in code_lines:
        if code.startswith("import "):
            for imported in code.removeprefix("import ").split(","):
                parts = imported.strip().split()
                if not parts:
                    continue
                module_name = parts[0]
                bound_name = parts[2] if len(parts) >= 3 and parts[1] == "as" else module_name.split(".", 1)[0]
                if bound_name == receiver and module_name not in {"re", "regex"}:
                    return True
        elif code.startswith("from "):
            match = re.match(r"from\s+([A-Za-z_][\w.]*)\s+import\s+(.+)", code)
            if not match or match.group(1) in {"re", "regex"}:
                continue
            for imported in match.group(2).split(","):
                parts = imported.strip().split()
                if not parts:
                    continue
                imported_name = parts[0]
                bound_name = parts[2] if len(parts) >= 3 and parts[1] == "as" else imported_name
                if bound_name == receiver:
                    return True
    return False


def regex_receiver_alias_compile_is_mutated(receiver: str, text: str) -> bool:
    aliases = {receiver}
    while True:
        escaped_aliases = "|".join(sorted((re.escape(alias) for alias in aliases), key=len, reverse=True))
        alias_assignment_pattern = re.compile(
            rf"(?m)(?:^|[;:])\s*(?P<alias>{JS_IDENTIFIER_RE})\s*(?::[^=\n]+)?="
            rf"\s*\(?\s*(?:{escaped_aliases})\s*\)?\s*(?:$|[;#\n])"
        )
        new_aliases = {match.group("alias") for match in alias_assignment_pattern.finditer(text)} - aliases
        if not new_aliases:
            break
        aliases.update(new_aliases)

    escaped_aliases = "|".join(sorted((re.escape(alias) for alias in aliases), key=len, reverse=True))
    if not escaped_aliases:
        return False

    return any(
        re.search(pattern, text)
        for pattern in (
            rf"(?m)(?:^|[;:])\s*(?:{escaped_aliases})\s*\.\s*compile\s*=",
            rf"\b(?:{escaped_aliases})\s*\.\s*__setattr__\s*\(\s*['\"]compile['\"]\s*,",
            rf"\b(?:{JS_IDENTIFIER_RE}\.)?__setattr__\s*\(\s*(?:{escaped_aliases})\s*,\s*['\"]compile['\"]\s*,",
            rf"\b(?:{JS_IDENTIFIER_RE}\.)?setattr\s*\(\s*(?:{escaped_aliases})\s*,\s*['\"]compile['\"]\s*,",
            rf"(?:{escaped_aliases})\s*\.\s*__dict__\s*\[\s*['\"]compile['\"]\s*\]\s*=",
            rf"(?:{escaped_aliases})\s*\.\s*__dict__\s*\.\s*__setitem__\s*\(\s*['\"]compile['\"]\s*,",
            rf"(?:{escaped_aliases})\s*\.\s*__dict__\s*\.\s*update\s*\([\s\S]{{0,500}}\bcompile\s*=",
            rf"(?:{escaped_aliases})\s*\.\s*__dict__\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]compile['\"]\s*:",
            rf"\bvars\s*\(\s*(?:{escaped_aliases})\s*\)\s*\[\s*['\"]compile['\"]\s*\]\s*=",
            rf"\bvars\s*\(\s*(?:{escaped_aliases})\s*\)\s*\.\s*__setitem__\s*\(\s*['\"]compile['\"]\s*,",
            rf"\bvars\s*\(\s*(?:{escaped_aliases})\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}\bcompile\s*=",
            rf"\bvars\s*\(\s*(?:{escaped_aliases})\s*\)\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]compile['\"]\s*:",
        )
    )


def python_shadow_text_for_call_scope(text: str, call_indent: int) -> str:
    lines = text.splitlines()
    scope_body_start = python_current_scope_body_start(lines, call_indent)
    scoped_lines = []
    continuation_depth = 0
    for index, line in enumerate(lines):
        code = line.partition("#")[0]
        if not code.strip():
            scoped_lines.append("")
            continue
        indent = len(code) - len(code.lstrip(" \t"))
        in_current_scope = index >= scope_body_start
        keep_line = indent < call_indent or (in_current_scope and indent <= call_indent) or continuation_depth > 0
        scoped_lines.append(code if keep_line else "")
        if keep_line:
            continuation_depth = max(0, continuation_depth + python_bracket_delta(code))
    return "\n".join(scoped_lines)


def python_current_scope_body_start(lines: list[str], call_indent: int) -> int:
    if call_indent <= 0:
        return 0
    for index in range(len(lines) - 1, -1, -1):
        code = lines[index].partition("#")[0]
        if not code.strip():
            continue
        indent = len(code) - len(code.lstrip(" \t"))
        stripped = code.strip()
        if indent < call_indent and re.match(r"(?:async\s+def|def|class)\b.*:\s*$", stripped):
            return index + 1
    return 0


def python_bracket_delta(line: str) -> int:
    delta = 0
    quote: str | None = None
    escaped = False
    for char in line:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "([{":
            delta += 1
        elif char in ")]}":
            delta -= 1
    return delta


def receiver_is_bound_later_in_comprehension(receiver: str, text: str, match_start: int) -> bool:
    escaped = re.escape(receiver)
    window = text[match_start : match_start + 500]
    for match in re.finditer(r"\bfor\b(?P<target>[^\n]{0,250}?)\bin\b", window):
        if re.search(rf"\b{escaped}\b", match.group("target")):
            return True
    return False


def receiver_is_rebound_later_in_enclosing_scope(
    receiver: str,
    text: str,
    match_start: int,
    call_indent: int,
) -> bool:
    if call_indent <= 0:
        return False

    escaped = re.escape(receiver)
    for line in text[match_start:].splitlines()[1:]:
        code = line.partition("#")[0]
        if not code.strip():
            continue
        indent = len(code) - len(code.lstrip(" \t"))
        if indent >= call_indent:
            continue
        stripped = code.strip()
        if re.match(rf"{escaped}\s*(?::[^=\n]+)?=", stripped):
            return True
        if re.match(rf"(?:global|nonlocal)\s+.*\b{escaped}\b", stripped):
            return True
        if from_import_shadows_receiver(receiver, stripped):
            return True
        if stripped.startswith("import "):
            for imported in stripped.removeprefix("import ").split(","):
                parts = imported.strip().split()
                if not parts:
                    continue
                module_name = parts[0]
                bound_name = parts[2] if len(parts) >= 3 and parts[1] == "as" else module_name.split(".", 1)[0]
                if bound_name == receiver and module_name not in {"re", "regex"}:
                    return True
    return False


def receiver_is_bound_as_function_argument(receiver: str, text: str, call_indent: int) -> bool:
    if call_indent <= 0:
        return False
    escaped = re.escape(receiver)
    pattern = re.compile(
        r"(?m)^(?P<indent>[ \t]*)(?:async\s+def|def)\s+[A-Za-z_]\w*"
        r"\s*\((?P<args>[\s\S]{0,500}?)\)\s*:"
    )
    candidates = [match for match in pattern.finditer(text) if len(match.group("indent")) < call_indent]
    if not candidates:
        return False
    return bool(re.search(rf"\b{escaped}\b", candidates[-1].group("args")))


def receiver_is_bound_as_lambda_argument(receiver: str, text: str, call_indent: int) -> bool:
    escaped = re.escape(receiver)
    multiline_lambda_args_pattern = re.compile(r"\blambda\s+(?P<args>[\s\S]{0,500}?):\s*$")
    if any(re.search(rf"\b{escaped}\b", match.group("args")) for match in multiline_lambda_args_pattern.finditer(text)):
        return True

    lambda_args_pattern = re.compile(r"\blambda\s+(?P<args>[^:\n]{0,500}):")
    lines = text.splitlines()
    if lines and any(
        re.search(rf"\b{escaped}\b", match.group("args")) for match in lambda_args_pattern.finditer(lines[-1])
    ):
        return True
    if call_indent <= 0:
        return False
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" \t"))
        if indent < call_indent and any(
            re.search(rf"\b{escaped}\b", match.group("args")) for match in lambda_args_pattern.finditer(line)
        ):
            return True
    return False


def python_receiver_is_shadowed_by_ast(receiver: str, text: str, *, call_indent: int) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        try:
            tree = ast.parse(f"{text}pass\n")
        except SyntaxError:
            return False

    lines = text.splitlines()
    scope_body_start = python_current_scope_body_start(lines, call_indent)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def node_reaches_call_scope(node: ast.AST) -> bool:
        if node_has_nested_scope_ancestor(node):
            return False
        line_index = getattr(node, "lineno", 1) - 1
        col_offset = getattr(node, "col_offset", 0)
        if line_index < scope_body_start:
            return col_offset < call_indent
        return True

    def node_is_current_scope_header(node: ast.AST) -> bool:
        return getattr(node, "lineno", 1) - 1 == scope_body_start - 1

    def node_has_nested_scope_ancestor(node: ast.AST) -> bool:
        parent = parents.get(node)
        while parent is not None:
            if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                if not node_is_current_scope_header(parent):
                    parent_line = getattr(parent, "lineno", 1) - 1
                    parent_col = getattr(parent, "col_offset", 0)
                    if parent_line >= scope_body_start or parent_col >= call_indent:
                        return True
            parent = parents.get(parent)
        return False

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node_reaches_call_scope(node) and function_global_rebinds_name(node, receiver):
                return True
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == receiver:
            if node_reaches_call_scope(node):
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            if node_is_current_scope_header(node) and ast_arguments_bind_name(node.args, receiver):
                return True
        elif isinstance(node, ast.Assign):
            if node_reaches_call_scope(node) and any(ast_target_binds_name(target, receiver) for target in node.targets):
                return True
            if node_reaches_call_scope(node) and any(
                ast_target_mutates_compile_attr(target, receiver) for target in node.targets
            ):
                return True
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if node_reaches_call_scope(node) and ast_target_binds_name(node.target, receiver):
                return True
            if node_reaches_call_scope(node) and ast_target_mutates_compile_attr(node.target, receiver):
                return True
        elif isinstance(node, ast.Call):
            if node_reaches_call_scope(node) and ast_call_mutates_compile_attr(node, receiver):
                return True
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if node_reaches_call_scope(node) and ast_target_binds_name(node.target, receiver):
                return True
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            if node_reaches_call_scope(node):
                for item in node.items:
                    if item.optional_vars is not None and ast_target_binds_name(item.optional_vars, receiver):
                        return True
        elif isinstance(node, ast.ExceptHandler):
            if node_reaches_call_scope(node) and node.name == receiver:
                return True
        elif isinstance(node, ast.match_case):
            pattern = node.pattern
            if node_reaches_call_scope(pattern) and ast_pattern_binds_name(pattern, receiver):
                return True
        elif isinstance(node, ast.Import):
            if node_reaches_call_scope(node):
                for alias in node.names:
                    bound_name = alias.asname or alias.name.split(".", 1)[0]
                    if bound_name == receiver and alias.name not in {"re", "regex"}:
                        return True
        elif isinstance(node, ast.ImportFrom):
            if node_reaches_call_scope(node):
                for alias in node.names:
                    if alias.name == "*" and node.module not in {"re", "regex"}:
                        return True
                    bound_name = alias.asname or alias.name
                    if bound_name == receiver:
                        return True
    return False


def function_global_rebinds_name(node: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    if not any(isinstance(child, ast.Global) and name in child.names for child in ast.walk(node)):
        return False

    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == name:
            return True
        if isinstance(child, ast.Assign):
            if any(ast_target_binds_name(target, name) for target in child.targets):
                return True
        elif isinstance(child, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if ast_target_binds_name(child.target, name):
                return True
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            if ast_target_binds_name(child.target, name):
                return True
        elif isinstance(child, (ast.With, ast.AsyncWith)):
            if any(item.optional_vars is not None and ast_target_binds_name(item.optional_vars, name) for item in child.items):
                return True
        elif isinstance(child, ast.ExceptHandler):
            if child.name == name:
                return True
        elif isinstance(child, ast.Import):
            for alias in child.names:
                if (alias.asname or alias.name.split(".", 1)[0]) == name:
                    return True
        elif isinstance(child, ast.ImportFrom):
            for alias in child.names:
                if (alias.asname or alias.name) == name:
                    return True
    return False


def ast_arguments_bind_name(arguments: ast.arguments, name: str) -> bool:
    positional = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    optional = [arguments.vararg, arguments.kwarg]
    return any(arg.arg == name for arg in positional) or any(arg is not None and arg.arg == name for arg in optional)


def ast_pattern_binds_name(pattern: ast.AST, name: str) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.name == name or (
            pattern.pattern is not None and ast_pattern_binds_name(pattern.pattern, name)
        )
    if isinstance(pattern, ast.MatchStar):
        return pattern.name == name
    if isinstance(pattern, ast.MatchMapping):
        return pattern.rest == name or any(ast_pattern_binds_name(item, name) for item in pattern.patterns)
    if isinstance(pattern, ast.MatchSequence):
        return any(ast_pattern_binds_name(item, name) for item in pattern.patterns)
    if isinstance(pattern, ast.MatchClass):
        return any(ast_pattern_binds_name(item, name) for item in (*pattern.patterns, *pattern.kwd_patterns))
    if isinstance(pattern, ast.MatchOr):
        return any(ast_pattern_binds_name(item, name) for item in pattern.patterns)
    return False


def ast_target_binds_name(target: ast.AST, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(ast_target_binds_name(element, name) for element in target.elts)
    if isinstance(target, ast.Starred):
        return ast_target_binds_name(target.value, name)
    return False


def ast_target_mutates_compile_attr(target: ast.AST, receiver: str) -> bool:
    if isinstance(target, ast.Attribute):
        return target.attr == "compile" and ast_expr_is_name(target.value, receiver)
    if isinstance(target, ast.Subscript):
        return (
            ast_expr_is_receiver_attr_dict(target.value, receiver)
            or ast_expr_is_vars_receiver_call(target.value, receiver)
        ) and ast_static_string(target.slice) == "compile"
    return False


def ast_call_mutates_compile_attr(node: ast.Call, receiver: str) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "setattr":
        return (
            len(node.args) >= 2
            and ast_expr_is_name(node.args[0], receiver)
            and ast_static_string(node.args[1]) == "compile"
        )
    if isinstance(node.func, ast.Attribute):
        if node.func.attr == "__setattr__":
            if ast_expr_is_name(node.func.value, receiver):
                return bool(node.args) and ast_static_string(node.args[0]) == "compile"
            if ast_expr_is_object_name(node.func.value):
                return (
                    len(node.args) >= 2
                    and ast_expr_is_name(node.args[0], receiver)
                    and ast_static_string(node.args[1]) == "compile"
                )
        if node.func.attr == "__setitem__":
            return (
                bool(node.args)
                and ast_static_string(node.args[0]) == "compile"
                and (
                    ast_expr_is_receiver_attr_dict(node.func.value, receiver)
                    or ast_expr_is_vars_receiver_call(node.func.value, receiver)
                )
            )
        if node.func.attr == "update" and (
            ast_expr_is_receiver_attr_dict(node.func.value, receiver)
            or ast_expr_is_vars_receiver_call(node.func.value, receiver)
        ):
            if any(keyword.arg == "compile" for keyword in node.keywords):
                return True
            return any(ast_mapping_has_static_key(arg, "compile") for arg in node.args)
    return False


def ast_expr_is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def ast_expr_is_object_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "object"


def ast_expr_is_receiver_attr_dict(node: ast.AST, receiver: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        and ast_expr_is_name(node.value, receiver)
    )


def ast_expr_is_vars_receiver_call(node: ast.AST, receiver: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and ast_expr_is_name(node.args[0], receiver)
    )


def ast_static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def ast_mapping_has_static_key(node: ast.AST, key: str) -> bool:
    return isinstance(node, ast.Dict) and any(ast_static_string(dict_key) == key for dict_key in node.keys if dict_key)


def from_import_shadows_receiver(receiver: str, text: str) -> bool:
    for match in re.finditer(
        r"(?ms)^\s*from\s+([A-Za-z_][\w.]*)\s+import\s*(?:\((?P<paren>.*?)\)|(?P<line>[^\n#]+))",
        text,
    ):
        if match.group(1) in {"re", "regex"}:
            continue
        imports = match.group("paren") if match.group("paren") is not None else match.group("line")
        for imported in imports.split(","):
            parts = imported.strip().split()
            if not parts:
                continue
            if parts[0] == "*":
                return True
            imported_name = parts[0]
            bound_name = parts[2] if len(parts) >= 3 and parts[1] == "as" else imported_name
            if bound_name == receiver:
                return True
    return False


def python_sys_modules_spoofs_module(text: str, module_names: set[str]) -> bool:
    for module_name in module_names:
        escaped = re.escape(module_name)
        if any(
            re.search(pattern, text)
            for pattern in (
                rf"\bsys\s*\.\s*modules\s*\[\s*['\"]{escaped}['\"]\s*\]\s*=",
                rf"\bsys\s*\.\s*modules\s*\.\s*__setitem__\s*\(\s*['\"]{escaped}['\"]\s*,",
                rf"\bsys\s*\.\s*modules\s*\.\s*update\s*\([\s\S]{{0,500}}\b{escaped}\s*=",
                rf"\bsys\s*\.\s*modules\s*\.\s*update\s*\([\s\S]{{0,500}}['\"]{escaped}['\"]\s*:",
            )
        ):
            return True
    return False


def is_dynamic_compile_call(
    is_python_file: bool,
    safe_regex_receivers: set[str],
    receiver: str | None,
    args: list[str],
    args_text: str,
) -> bool:
    if receiver and receiver not in safe_regex_receivers:
        return True
    if receiver is None:
        return True
    return has_python_compile_args(args, args_text)


def has_python_compile_args(args: list[str], _args_text: str) -> bool:
    stripped_args = [arg.strip() for arg in args]
    return (
        len(stripped_args) >= 3
        or any(arg.split("=", 1)[0].strip() == "mode" for arg in stripped_args)
        or any(arg.startswith("*") for arg in stripped_args)
    )


def extract_call_args(text: str, open_paren: int) -> str | None:
    if open_paren < 0 or open_paren >= len(text) or text[open_paren] != "(":
        return None

    depth = 0
    quote: str | None = None
    triple_quote = False
    i = open_paren + 1
    while i < len(text):
        char = text[i]
        if quote is not None:
            if triple_quote and text.startswith(quote * 3, i):
                quote = None
                triple_quote = False
                i += 3
                continue
            if not triple_quote:
                if char == "\\":
                    i += 2
                    continue
                if char == quote:
                    quote = None
            i += 1
            continue

        if char in {"'", '"'}:
            quote = char
            triple_quote = text.startswith(char * 3, i)
            i += 3 if triple_quote else 1
            continue
        if char == "#":
            newline = text.find("\n", i)
            if newline == -1:
                return None
            i = newline + 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0 and char == ")":
                return text[open_paren + 1 : i]
            depth -= 1
        i += 1
    return None


def split_top_level_args(args_text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    triple_quote = False
    i = 0
    while i < len(args_text):
        char = args_text[i]
        if quote is not None:
            if triple_quote and args_text.startswith(quote * 3, i):
                quote = None
                triple_quote = False
                i += 3
                continue
            if not triple_quote:
                if char == "\\":
                    i += 2
                    continue
                if char == quote:
                    quote = None
            i += 1
            continue

        if char in {"'", '"'}:
            quote = char
            triple_quote = args_text.startswith(char * 3, i)
            i += 3 if triple_quote else 1
            continue
        if char == "#":
            newline = args_text.find("\n", i)
            if newline == -1:
                break
            i = newline + 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(args_text[start:i].strip())
            start = i + 1
        i += 1

    args.append(args_text[start:].strip())
    while args and not args[-1]:
        args.pop()
    return args


def audit_dependency_file(rel_path: str, text: str) -> list[Finding]:
    path_name = Path(rel_path).name.lower()
    findings: list[Finding] = []
    if path_name == "requirements.txt":
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" not in line and " @ " not in line:
                findings.append(
                    Finding("WARNING", "unpinned-python-dependency", rel_path, line_number, "Python dependency is not pinned.")
                )
    elif path_name == "package.json":
        findings.extend(audit_package_json(rel_path, text))
    elif path_name in {"pyproject.toml", "setup.py", "setup.cfg", "pnpm-lock.yaml", "package-lock.json"}:
        findings.append(Finding("WARNING", "dependency-manifest", rel_path, None, "Dependency manifest requires manual review."))
    return findings


def audit_package_json(rel_path: str, text: str) -> list[Finding]:
    try:
        package = json.loads(text)
    except json.JSONDecodeError:
        return [Finding("WARNING", "invalid-package-json", rel_path, None, "package.json could not be parsed.")]

    findings: list[Finding] = [
        Finding("WARNING", "dependency-manifest", rel_path, None, "package.json requires manual review.")
    ]
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = package.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, spec in sorted(deps.items()):
            if not isinstance(spec, str) or spec in {"*", "latest"} or spec.startswith(("^", "~", ">")):
                findings.append(
                    Finding("WARNING", "loose-node-dependency", rel_path, None, f"{section} entry is loosely pinned: {name}.")
                )
    return findings


def read_text(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix not in TEXT_SUFFIXES and path.name not in {"SKILL.md", "openai.yaml"}:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    if len(raw) > MAX_TEXT_BYTES:
        raw = raw[:MAX_TEXT_BYTES]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def looks_like_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ("example", "placeholder", "replace-me", "dummy", "test"))


def extract_skill_name(root: Path) -> str | None:
    skill_md = root / "SKILL.md"
    text = read_text(skill_md)
    if text is None:
        return None
    for raw_line in text.splitlines():
        if raw_line.strip().startswith("name:"):
            return raw_line.split(":", 1)[1].strip().strip("'\"")
    return None


def count_files(root: Path) -> int:
    return sum(1 for _ in iter_skill_files(root))


def compute_manifest_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(iter_skill_files(root), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK\0")
            digest.update(os.readlink(path).encode("utf-8"))
            digest.update(b"\0")
            continue
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"UNREADABLE")
        digest.update(b"\0")
    return digest.hexdigest()
