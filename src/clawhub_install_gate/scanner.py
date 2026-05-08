from __future__ import annotations

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
)

WARNING_RULES = (
    Rule(
        "network-client",
        "WARNING",
        re.compile(
            r"\b(requests\.|urllib\.request|httpx\.|fetch\(|XMLHttpRequest|"
            r"curl\b|wget\b|socket\.|WebSocket)\b",
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
        re.compile(r"\b(eval\(|exec\(|compile\(|new Function\(|pickle\.loads|marshal\.loads)\b"),
        "Dynamic code execution requires manual review.",
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

    for path in iter_skill_files(root):
        rel_path = path.relative_to(root).as_posix()
        findings.extend(audit_file_metadata(root, path, rel_path))
        if path.is_symlink():
            continue
        text = read_text(path)
        if text is None:
            findings.extend(audit_binary_file(path, rel_path))
            continue
        findings.extend(audit_text_file(rel_path, text))
        findings.extend(audit_dependency_file(rel_path, text))

    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.path, item.code))


def iter_skill_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if path.is_file() or path.is_symlink():
            yield path


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


def audit_text_file(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if "TODO:" in text or "[TODO" in text:
        findings.append(Finding("WARNING", "template-marker", rel_path, None, "Template TODO marker remains in the skill."))

    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in (*SECRET_RULES, *BLOCK_RULES, *WARNING_RULES):
            if rule.pattern.search(line):
                if rule in SECRET_RULES and looks_like_placeholder(line):
                    continue
                findings.append(Finding(rule.severity, rule.code, rel_path, line_number, rule.message))
    return findings


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
