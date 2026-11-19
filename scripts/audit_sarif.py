#!/usr/bin/env python3
"""SARIF-2.1.0-Exporter und zentraler Regelkatalog für skill_audit.py (v1.6-DE).

Eigenständiges, abhängigkeitsfreies Modul (Python 3.10+ Stdlib) zur Normalisierung
von Audit-Befunden aus ``skill_audit.audit_directory()`` (kompatibel mit v1.3-,
v1.4-, v1.5- und v1.6-Report-Strukturen) sowie zur Serialisierung als SARIF-2.1.0-Dokument.

Nutzung:
  python3 scripts/audit_sarif.py --self-test
  python3 scripts/audit_sarif.py <audit-report.json> [--output report.sarif]
  python3 scripts/skill_audit.py <ziel> --json | python3 scripts/audit_sarif.py -
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "skill-verbesserungsanalyse"
TOOL_INFORMATION_URI = "https://github.com/GermanAutodidact/skill-verbesserungsanalyse"

TOOL_VERSION = "1.6-DE"
RULE_COUNT = 28

# Stabiler Regelkatalog (SV-P1-01 .. SV-P3-10) für alle v1.3- bis v1.6-Prüfungen.
RULES: dict[str, dict[str, str]] = {
    # --- P1 (level="error") ---
    "SV-P1-01": {
        "priority": "P1",
        "level": "error",
        "name": "UnclosedCodeBlock",
        "short_description": "Unclosed fenced code block in Markdown file",
        "full_description": (
            "A fenced code block (``` or ~~~) is not properly closed before EOF or a "
            "subsequent block, breaking Markdown parsing and downstream checks."
        ),
        "category": "syntax",
    },
    "SV-P1-02": {
        "priority": "P1",
        "level": "error",
        "name": "InvalidEvalsJson",
        "short_description": "Invalid JSON in evals/cases.json",
        "full_description": (
            "evals/cases.json cannot be parsed as valid JSON, preventing automated "
            "evaluation and schema verification."
        ),
        "category": "evals",
    },
    "SV-P1-03": {
        "priority": "P1",
        "level": "error",
        "name": "SandboxAntiPattern",
        "short_description": "Sandbox anti-pattern (sudo/apt-get) in shell block",
        "full_description": (
            "Shell code block uses privileged system commands such as sudo or apt-get "
            "that fail inside unprivileged cloud sandboxes."
        ),
        "category": "sandbox",
    },
    "SV-P1-04": {
        "priority": "P1",
        "level": "error",
        "name": "UnicodeSmugglingOrBidi",
        "short_description": "Unicode tag smuggling or Bidi trojan-source override",
        "full_description": (
            "File contains invisible Unicode tag smuggling characters (U+E0000–U+E007F) "
            "or bidirectional override controls (Trojan Source) that can conceal prompts "
            "or code."
        ),
        "category": "security",
    },
    "SV-P1-05": {
        "priority": "P1",
        "level": "error",
        "name": "DangerousScriptPattern",
        "short_description": "Dangerous script execution or credential-access pattern",
        "full_description": (
            "Bundled script contains high-risk execution patterns such as eval/exec, "
            "subprocess shell=True, os.system, credential file access, or curl|sh."
        ),
        "category": "security",
    },
    "SV-P1-06": {
        "priority": "P1",
        "level": "error",
        "name": "HardcodedSecret",
        "short_description": "Hardcoded secret, API token, or private key",
        "full_description": (
            "File contains a hardcoded API key, token, credential, or PEM private key "
            "block that must not be stored in a skill repository."
        ),
        "category": "security",
    },
    # --- P2 (level="warning") ---
    "SV-P2-01": {
        "priority": "P2",
        "level": "warning",
        "name": "BrokenMarkdownLink",
        "short_description": "Broken relative Markdown link or #anchor",
        "full_description": (
            "Relative Markdown link points to a missing local target file or a "
            "non-existent heading anchor."
        ),
        "category": "integrity",
    },
    "SV-P2-02": {
        "priority": "P2",
        "level": "warning",
        "name": "DeadLocalReference",
        "short_description": "Dead local file or script reference in backticks",
        "full_description": (
            "Inline backtick reference names a local script or document that does not "
            "exist in the audited skill or repository."
        ),
        "category": "integrity",
    },
    "SV-P2-03": {
        "priority": "P2",
        "level": "warning",
        "name": "OrphanBundledFile",
        "short_description": "Orphan file in scripts/, references/, or assets/ not referenced from SKILL.md",
        "full_description": (
            "A bundled resource under scripts/, references/, or assets/ is never "
            "referenced from SKILL.md and may be dead weight or unreachable by agents."
        ),
        "category": "integrity",
    },
    "SV-P2-04": {
        "priority": "P2",
        "level": "warning",
        "name": "MarkdownFormatLint",
        "short_description": "Markdown formatting issue (missing space or trailing whitespace)",
        "full_description": (
            "Prose contains punctuation/bold spacing errors or trailing whitespace "
            "outside fenced code blocks."
        ),
        "category": "format",
    },
    "SV-P2-05": {
        "priority": "P2",
        "level": "warning",
        "name": "MermaidSyntaxLint",
        "short_description": "Mermaid diagram syntax or compatibility issue",
        "full_description": (
            "Mermaid fenced code block uses unsupported diagram types, HTML tags, or "
            "unquoted node labels containing parentheses."
        ),
        "category": "syntax",
    },
    "SV-P2-06": {
        "priority": "P2",
        "level": "warning",
        "name": "EvalsSchemaError",
        "short_description": "Schema validation error in evals/cases.json",
        "full_description": (
            "evals/cases.json violates required eval schema rules (duplicate IDs, "
            "missing prompt/must_contain, wrong types, or missing expected_modules)."
        ),
        "category": "evals",
    },
    "SV-P2-07": {
        "priority": "P2",
        "level": "warning",
        "name": "FrontmatterFileNamesMismatch",
        "short_description": "SKILL.md frontmatter file_names entry missing or invalid",
        "full_description": (
            "An entry listed in SKILL.md frontmatter file_names does not exist in the "
            "skill folder or references compiled bytecode."
        ),
        "category": "integrity",
    },
    "SV-P2-08": {
        "priority": "P2",
        "level": "warning",
        "name": "BytecodeOrJunkFile",
        "short_description": "Bytecode or OS junk file present (__pycache__, .pyc, .DS_Store)",
        "full_description": (
            "Repository or skill directory contains Python bytecode or OS metadata "
            "junk files that pollute skill bundles."
        ),
        "category": "hygiene",
    },
    "SV-P2-09": {
        "priority": "P2",
        "level": "warning",
        "name": "AgentSkillsSpecError",
        "short_description": "agentskills.io specification error in SKILL.md frontmatter",
        "full_description": (
            "SKILL.md frontmatter violates hard agentskills.io specification rules "
            "(spec-invalid-name or spec-invalid-compatibility)."
        ),
        "category": "spec",
    },
    "SV-P2-10": {
        "priority": "P2",
        "level": "warning",
        "name": "InvisibleUnicodeCharacter",
        "short_description": "Invisible Unicode zero-width or control character detected",
        "full_description": (
            "File contains zero-width spaces/joiners or invisible control characters "
            "(unicode-zero-width or unicode-invisible-control) that impair reviewability."
        ),
        "category": "security",
    },
    "SV-P2-11": {
        "priority": "P2",
        "level": "warning",
        "name": "UnsafeScriptDeserialization",
        "short_description": "Unsafe deserialization in bundled script",
        "full_description": (
            "Bundled script uses unsafe deserialization primitives such as pickle, "
            "marshal, shelve, or unsafe yaml.load (script-unsafe-deserialize)."
        ),
        "category": "security",
    },
    "SV-P2-12": {
        "priority": "P2",
        "level": "warning",
        "name": "ProcessLifecycleRisk",
        "short_description": "Missing process lifecycle cleanup or orphan-process guard in script or sidecar",
        "full_description": (
            "Bundled script or sidecar starts background subprocesses, servers, or "
            "restart_policy=always workers without lifecycle cleanup (atexit/signal, "
            "parent-PID watchdog, single-instance lock, daemon_threads, or wait timeout), "
            "risking leftover orphaned or duplicate background processes."
        ),
        "category": "reliability",
    },
    # --- P3 (level="note") ---
    "SV-P3-01": {
        "priority": "P3",
        "level": "note",
        "name": "SkillDescriptionLength",
        "short_description": "SKILL.md description missing or exceeds 1024 characters",
        "full_description": (
            "SKILL.md frontmatter description is empty or exceeds the 1024-character "
            "discovery budget recommended for skill routing."
        ),
        "category": "frontmatter",
    },
    "SV-P3-02": {
        "priority": "P3",
        "level": "note",
        "name": "MissingEnglishTrigger",
        "short_description": "Missing English trigger phrase in SKILL.md description",
        "full_description": (
            "SKILL.md description lacks an English trigger clause (e.g. 'Use when ...') "
            "for bilingual agent activation."
        ),
        "category": "frontmatter",
    },
    "SV-P3-03": {
        "priority": "P3",
        "level": "note",
        "name": "HardcodedPlatformPath",
        "short_description": "Hardcoded user or platform-specific path",
        "full_description": (
            "Markdown prose or shell block references a non-portable local path such "
            "as ~/.gemini/ or /Users/... without portable context."
        ),
        "category": "portability",
    },
    "SV-P3-04": {
        "priority": "P3",
        "level": "note",
        "name": "ContextBudgetOrTocWarning",
        "short_description": "Context budget, file size, or missing TOC warning",
        "full_description": (
            "A large Markdown file lacks a table of contents, exceeds recommended "
            "token budgets, or the skill bundle exceeds the 46 KB resource limit."
        ),
        "category": "budget",
    },
    "SV-P3-05": {
        "priority": "P3",
        "level": "note",
        "name": "AgentSkillsSpecAdvisory",
        "short_description": "agentskills.io specification advisory in SKILL.md frontmatter",
        "full_description": (
            "SKILL.md frontmatter triggers an agentskills.io advisory such as "
            "spec-name-dir-mismatch or spec-nonstandard-field."
        ),
        "category": "spec",
    },
    "SV-P3-06": {
        "priority": "P3",
        "level": "note",
        "name": "CrossLanguageContamination",
        "short_description": "Cross-language code contamination detected in SKILL.md",
        "full_description": (
            "SKILL.md mixes three or more unrelated application programming language "
            "families without multi-interface tool context, which can degrade agent focus."
        ),
        "category": "quality",
    },
    "SV-P3-07": {
        "priority": "P3",
        "level": "note",
        "name": "ProseOrWorkflowQuality",
        "short_description": "README-tier heading or missing workflow verification in SKILL.md",
        "full_description": (
            "SKILL.md contains README-style boilerplate headings or lacks explicit "
            "verification/exit steps in its workflow."
        ),
        "category": "quality",
    },
    "SV-P3-08": {
        "priority": "P3",
        "level": "note",
        "name": "EvalQualityAdvisory",
        "short_description": "Eval quality advisory (negative-trigger coverage or prompt leakage)",
        "full_description": (
            "evals/cases.json lacks negative-trigger test coverage or shows signs of "
            "prompt/answer leakage reducing evaluation signal."
        ),
        "category": "evals",
    },
    "SV-P3-09": {
        "priority": "P3",
        "level": "note",
        "name": "PurposeAlignmentAdvisory",
        "short_description": "Purpose-vs-architecture alignment advisory in SKILL.md",
        "full_description": (
            "SKILL.md description lacks an explicit negative scope boundary (e.g. 'Don't use for ...') "
            "or advertises bundled scripts that are missing from scripts/."
        ),
        "category": "purpose",
    },
    "SV-P3-10": {
        "id": "SV-P3-10",
        "priority": "P3",
        "level": "note",
        "name": "VersionRuleConsistencyAdvisory",
        "short_description": "Version or rule-registry drift between code, docs, and evals",
        "full_description": (
            "Reports inconsistencies between the central TOOL_VERSION / RULES registry and "
            "version or rule references in SKILL.md, README.md, CHANGELOG.md, "
            "references/PRUEFKATALOG.md, or evals/cases.json."
        ),
        "help_text": (
            "Synchronize version strings (TOOL_VERSION) and rule counts/IDs across SKILL.md, "
            "README.md, CHANGELOG.md, references/PRUEFKATALOG.md, and evals/cases.json."
        ),
        "category": "consistency",
    },
}

assert len(RULES) == RULE_COUNT, f"Expected {RULE_COUNT} rules in RULES, got {len(RULES)}"

_BACKTICK_FILE_RE = re.compile(r"^`([^`]+)`")
_P1_UNICODE_KINDS = {"unicode-tag-smuggling", "unicode-bidi-override"}
_P2_UNICODE_KINDS = {"unicode-zero-width", "unicode-invisible-control"}
_P1_SECRET_KINDS = {"hardcoded-secret", "private-key", "hardcoded-private-key", "secret-leak"}
_P2_DESERIALIZE_KINDS = {"script-unsafe-deserialize", "unsafe-deserialize"}
_P2_SPEC_KINDS = {"spec-invalid-name", "spec-invalid-compatibility"}
_P3_SPEC_KINDS = {"spec-name-dir-mismatch", "spec-nonstandard-field"}


def _normalize_file(value: object, default: str = "SKILL.md") -> str:
    """Normalizes a relative file path to POSIX format without leading './'."""
    if not isinstance(value, str):
        return default
    cleaned = value.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned or default


def _normalize_line(value: object) -> int | None:
    """Returns a positive integer line number or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _make_finding(
    rule_id: str,
    file_path: object,
    line: object,
    message: str,
    *,
    default_file: str = "SKILL.md",
    confidence: str | None = None,
) -> dict[str, object]:
    """Constructs a normalized finding dict backed by RULES metadata."""
    meta = RULES[rule_id]
    text = message.strip() or meta["short_description"]
    finding: dict[str, object] = {
        "rule_id": rule_id,
        "priority": meta["priority"],
        "level": meta["level"],
        "file": _normalize_file(file_path, default=default_file),
        "line": _normalize_line(line),
        "message": text,
    }
    if confidence in {"verified", "heuristic"}:
        finding["confidence"] = confidence
    return finding


def _extract_item_message(item: dict[str, Any], fallback: str) -> str:
    """Extracts a descriptive message from a heterogeneous issue dictionary."""
    for key in ("message", "detail", "reason", "description"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    kind = str(item.get("kind", "")).strip()
    codepoint = str(item.get("codepoint", "")).strip()
    char_name = str(item.get("name", "")).strip()
    snippet = str(item.get("snippet", "")).strip()
    if codepoint:
        label = f"{kind} ({codepoint} {char_name})".strip() if kind else f"{codepoint} {char_name}".strip()
        return f"{label}: {snippet}" if snippet else label
    if kind and snippet:
        return f"{kind}: {snippet}"
    if snippet:
        return snippet
    if kind:
        return f"{fallback} ({kind})"
    return fallback


def _iter_list(value: object) -> list[Any]:
    """Safely unwraps a list or tuple into a Python list."""
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _collect_security_items(report: dict[str, object]) -> list[Any]:
    """Collects security findings from unified or split v1.4 report keys."""
    items: list[Any] = []
    sec = report.get("security_issues")
    if isinstance(sec, list):
        items.extend(sec)
    elif isinstance(sec, dict):
        for subkey in ("findings", "issues", "unicode", "scripts", "secrets"):
            items.extend(_iter_list(sec.get(subkey)))
    for extra_key in (
        "unicode_smuggling_issues",
        "unicode_issues",
        "script_security_issues",
        "secret_issues",
    ):
        items.extend(_iter_list(report.get(extra_key)))
    return items


def _classify_security_rule(item: dict[str, Any]) -> str:
    """Maps a security issue dict to SV-P1-04/05/06 or SV-P2-10/11."""
    kind = str(item.get("kind", "")).strip().lower()
    sev = str(item.get("severity", "")).strip().lower()
    if kind in _P1_UNICODE_KINDS or "bidi" in kind or "tag-smuggling" in kind:
        return "SV-P1-04"
    if kind in _P2_UNICODE_KINDS or "zero-width" in kind or "invisible-control" in kind:
        return "SV-P2-10"
    if kind in _P1_SECRET_KINDS or "secret" in kind or "private-key" in kind:
        return "SV-P1-06"
    if kind in _P2_DESERIALIZE_KINDS or "deserialize" in kind or "audit-ok" in kind or sev == "p2":
        return "SV-P2-11"
    return "SV-P1-05"


def _collect_spec_items(report: dict[str, object], fm: dict[str, Any]) -> list[Any]:
    """Collects agentskills.io spec issues from top-level or frontmatter keys."""
    for key in ("spec_issues", "agentskills_spec_issues", "frontmatter_spec_issues"):
        val = report.get(key)
        if isinstance(val, list):
            return val
    fm_spec = fm.get("spec_issues")
    if isinstance(fm_spec, list):
        return fm_spec
    return []


def _classify_spec_rule(item: dict[str, Any]) -> str:
    """Maps an agentskills.io spec issue dict to SV-P2-09 (error) or SV-P3-05 (advisory)."""
    kind = str(item.get("kind", "")).strip().lower()
    if kind in _P2_SPEC_KINDS:
        return "SV-P2-09"
    if kind in _P3_SPEC_KINDS:
        return "SV-P3-05"
    prio = str(item.get("priority", "")).strip().upper()
    sev = str(item.get("severity", item.get("level", ""))).strip().lower()
    if prio == "P2" or sev in {"p2", "error", "warning"}:
        return "SV-P2-09"
    return "SV-P3-05"


def check_version_and_rule_consistency(
    target: Path, fm: dict[str, object]
) -> list[dict[str, object]]:
    """Checks internal version consistency and (for skill-verbesserungsanalyse) SSOT alignment."""
    issues: list[dict[str, object]] = []
    target_path = Path(target)
    fm_ver_raw = fm.get("version")
    fm_ver = str(fm_ver_raw).strip() if fm_ver_raw is not None and str(fm_ver_raw).strip() else ""

    # a) General internal consistency (for ANY skill)
    if fm_ver:
        evals_file = target_path / "evals" / "cases.json"
        if evals_file.is_file():
            try:
                evals_data = json.loads(evals_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                evals_data = None
            if isinstance(evals_data, dict) and evals_data.get("version") is not None:
                ev_ver = str(evals_data.get("version", "")).strip()
                if ev_ver and ev_ver != fm_ver:
                    issues.append(
                        {
                            "file": "evals/cases.json",
                            "severity": "p3",
                            "kind": "version-mismatch-evals",
                            "confidence": "verified",
                            "message": f"Version in evals/cases.json ({ev_ver}) weicht von SKILL.md ({fm_ver}) ab.",
                        }
                    )

        changelog_file = target_path / "CHANGELOG.md"
        if changelog_file.is_file():
            changelog_text = changelog_file.read_text(encoding="utf-8", errors="replace")
            ver_base = re.sub(r"-[A-Za-z]+$", "", fm_ver)
            if fm_ver not in changelog_text and (not ver_base or ver_base not in changelog_text):
                issues.append(
                    {
                        "file": "CHANGELOG.md",
                        "severity": "p3",
                        "kind": "version-missing-in-changelog",
                        "confidence": "verified",
                        "message": f"SKILL.md-Version {fm_ver} ist nicht in CHANGELOG.md dokumentiert.",
                    }
                )

    # b) Self-consistency for skill-verbesserungsanalyse
    if str(fm.get("name", "")).strip() == "skill-verbesserungsanalyse":
        if fm_ver != TOOL_VERSION:
            issues.append(
                {
                    "file": "SKILL.md",
                    "severity": "p3",
                    "kind": "version-mismatch-ssot",
                    "confidence": "verified",
                    "message": (
                        f"SKILL.md-Version ({fm_ver or 'fehlt'}) weicht von "
                        f"TOOL_VERSION ({TOOL_VERSION}) in scripts/audit_sarif.py ab."
                    ),
                }
            )

        for rel_doc in ("README.md", "references/PRUEFKATALOG.md"):
            doc_path = target_path / rel_doc
            if doc_path.is_file():
                doc_text = doc_path.read_text(encoding="utf-8", errors="replace")
                if TOOL_VERSION not in doc_text:
                    issues.append(
                        {
                            "file": rel_doc,
                            "severity": "p3",
                            "kind": "version-drift-doc",
                            "confidence": "verified",
                            "message": (
                                f"`{rel_doc}` referenziert nicht die aktuelle TOOL_VERSION "
                                f"(`{TOOL_VERSION}`)."
                            ),
                        }
                    )

        pruefkatalog_path = target_path / "references" / "PRUEFKATALOG.md"
        if pruefkatalog_path.is_file():
            pk_text = pruefkatalog_path.read_text(encoding="utf-8", errors="replace")
            missing_rules = [rid for rid in sorted(RULES.keys()) if rid not in pk_text]
            rule_count_str = f"{len(RULES)}"
            if missing_rules or rule_count_str not in pk_text:
                details: list[str] = []
                if missing_rules:
                    details.append(f"fehlende Regel-IDs: {', '.join(missing_rules)}")
                if rule_count_str not in pk_text:
                    details.append(f"Regelanzahl {rule_count_str} fehlt")
                issues.append(
                    {
                        "file": "references/PRUEFKATALOG.md",
                        "severity": "p3",
                        "kind": "rule-registry-drift-doc",
                        "confidence": "verified",
                        "message": (
                            "Regelkatalog-Drift in `references/PRUEFKATALOG.md` "
                            f"({'; '.join(details)})."
                        ),
                    }
                )

    return issues


def extract_findings(report: dict[str, object]) -> list[dict[str, object]]:
    """Extracts normalized findings from an ``audit_directory()`` report dict.

    Gracefully handles missing v1.4/v1.5 keys via ``.get(...)`` so v1.3, v1.4, and v1.5
    reports are supported without errors.

    Returns a list of dicts with schema:
      ``{"rule_id": str, "priority": "P1"|"P2"|"P3", "level": "error"|"warning"|"note",
         "file": str, "line": int | None, "message": str}`` (plus optional ``"confidence"``).
    """
    if not isinstance(report, dict):
        return []

    summary_raw = report.get("summary")
    summary: dict[str, Any] = summary_raw if isinstance(summary_raw, dict) else {}
    fm_raw = report.get("frontmatter")
    fm: dict[str, Any] = fm_raw if isinstance(fm_raw, dict) else {}

    p1_findings: list[dict[str, object]] = []
    p2_findings: list[dict[str, object]] = []
    p3_findings: list[dict[str, object]] = []

    # --- SV-P1-01: Unclosed fenced code blocks ---
    unclosed_raw = summary.get("unclosed_code_blocks")
    if unclosed_raw is None:
        unclosed_raw = report.get("unclosed_code_blocks", [])
    for entry in _iter_list(unclosed_raw):
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            msg = _extract_item_message(entry, f"Ungeschlossener Codeblock in `{fpath}`")
            p1_findings.append(_make_finding("SV-P1-01", fpath, entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            p1_findings.append(
                _make_finding(
                    "SV-P1-01",
                    entry,
                    None,
                    f"Ungeschlossener Codeblock in `{_normalize_file(entry)}`.",
                )
            )

    # --- SV-P1-02 (invalid JSON) & SV-P2-06 (evals schema errors) ---
    for entry in _iter_list(report.get("evals_issues", [])):
        if isinstance(entry, dict):
            msg = _extract_item_message(entry, "Evals-Schema-Fehler in evals/cases.json")
            fpath = entry.get("file", "evals/cases.json")
            line = entry.get("line")
            kind = str(entry.get("kind", "")).lower()
            is_invalid_json = (
                "invalid-json" in kind
                or "ungültiges json" in msg.lower()
                or "invalid json" in msg.lower()
            )
        else:
            msg = str(entry).strip()
            fpath = "evals/cases.json"
            line = None
            is_invalid_json = "ungültiges json" in msg.lower() or "invalid json" in msg.lower()
        if is_invalid_json:
            p1_findings.append(
                _make_finding("SV-P1-02", fpath, line, msg, default_file="evals/cases.json")
            )
        elif msg:
            p2_findings.append(
                _make_finding("SV-P2-06", fpath, line, msg, default_file="evals/cases.json")
            )

    # --- SV-P1-03 (sandbox anti-patterns) & SV-P3-03 (hardcoded platform paths) ---
    for entry in _iter_list(report.get("portability_and_sandbox_issues", [])):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "")).strip()
        fpath = entry.get("file", "SKILL.md")
        line = entry.get("line")
        snippet = str(entry.get("snippet", "")).strip()
        if kind == "sandbox-anti-pattern":
            msg = f"Sandbox-Anti-Pattern in Shell-Block: {snippet}" if snippet else RULES["SV-P1-03"]["short_description"]
            p1_findings.append(_make_finding("SV-P1-03", fpath, line, msg))
        elif kind == "hardcoded-platform-path":
            msg = f"Hardcoded Plattform-Pfad: {snippet}" if snippet else RULES["SV-P3-03"]["short_description"]
            p3_findings.append(_make_finding("SV-P3-03", fpath, line, msg))

    # --- Security issues: SV-P1-04, SV-P1-05, SV-P1-06, SV-P2-10, SV-P2-11 ---
    for entry in _collect_security_items(report):
        if isinstance(entry, dict):
            rule_id = _classify_security_rule(entry)
            fpath = entry.get("file", "SKILL.md")
            line = entry.get("line")
            msg = _extract_item_message(entry, RULES[rule_id]["short_description"])
            finding = _make_finding(rule_id, fpath, line, msg)
        elif isinstance(entry, str) and entry.strip():
            lower = entry.lower()
            if "bidi" in lower or "tag-smuggling" in lower:
                rule_id = "SV-P1-04"
            elif "zero-width" in lower or "invisible-control" in lower:
                rule_id = "SV-P2-10"
            elif "secret" in lower or "private key" in lower or "private-key" in lower:
                rule_id = "SV-P1-06"
            elif "deserialize" in lower or "pickle" in lower:
                rule_id = "SV-P2-11"
            else:
                rule_id = "SV-P1-05"
            finding = _make_finding(rule_id, "SKILL.md", None, entry)
        else:
            continue

        if finding["priority"] == "P1":
            p1_findings.append(finding)
        else:
            p2_findings.append(finding)

    # --- SV-P2-01: Broken relative Markdown links or #anchors ---
    for entry in _iter_list(report.get("broken_links", [])):
        if not isinstance(entry, dict):
            continue
        link = str(entry.get("link", "")).strip()
        reason = str(entry.get("reason", "")).strip()
        if link and reason:
            msg = f"Defekter Link `{link}`: {reason}"
        else:
            msg = _extract_item_message(entry, RULES["SV-P2-01"]["short_description"])
        p2_findings.append(_make_finding("SV-P2-01", entry.get("file"), entry.get("line"), msg))

    # --- SV-P2-02: Dead local references in backticks ---
    for entry in _iter_list(report.get("dead_local_references", [])):
        if isinstance(entry, dict):
            ref = str(entry.get("reference", "")).strip()
            mentioned = _iter_list(entry.get("mentioned_in"))
            files = [str(f) for f in mentioned if isinstance(f, str) and f.strip()]
            primary_file = entry.get("file") or (files[0] if files else "SKILL.md")
            extra = f" (auch erwähnt in: {', '.join(files[1:])})" if len(files) > 1 else ""
            msg = (
                f"Toter lokaler Verweis `{ref}` nicht gefunden{extra}."
                if ref
                else _extract_item_message(entry, RULES["SV-P2-02"]["short_description"])
            )
            p2_findings.append(_make_finding("SV-P2-02", primary_file, entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            p2_findings.append(
                _make_finding("SV-P2-02", "SKILL.md", None, f"Toter lokaler Verweis `{entry}`.")
            )

    # --- SV-P2-03: Orphan files in scripts/references/assets ---
    orphan_raw = report.get("orphan_files")
    if orphan_raw is None:
        orphan_raw = report.get("orphaned_files")
    if orphan_raw is None:
        orphan_raw = report.get("unreferenced_files", [])
    for entry in _iter_list(orphan_raw):
        if isinstance(entry, dict):
            fpath = entry.get("file") or entry.get("path") or "SKILL.md"
            msg = _extract_item_message(
                entry,
                f"Verwaiste Datei `{_normalize_file(fpath)}` wird in SKILL.md nicht referenziert.",
            )
            p2_findings.append(_make_finding("SV-P2-03", fpath, entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            norm = _normalize_file(entry)
            p2_findings.append(
                _make_finding(
                    "SV-P2-03",
                    norm,
                    None,
                    f"Verwaiste Datei `{norm}` wird in SKILL.md nicht referenziert.",
                )
            )

    # --- SV-P2-04: Format lint ---
    for entry in _iter_list(report.get("format_issues", [])):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "")).strip()
        snippet = str(entry.get("snippet", "")).strip()
        if kind and snippet:
            msg = f"Formatierungsfehler ({kind}): {snippet}"
        else:
            msg = _extract_item_message(entry, RULES["SV-P2-04"]["short_description"])
        p2_findings.append(_make_finding("SV-P2-04", entry.get("file"), entry.get("line"), msg))

    # --- SV-P2-05: Mermaid syntax lint ---
    for entry in _iter_list(report.get("mermaid_issues", [])):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "")).strip()
        snippet = str(entry.get("snippet", "")).strip()
        if kind and snippet:
            msg = f"Mermaid-Lint ({kind}): {snippet}"
        else:
            msg = _extract_item_message(entry, RULES["SV-P2-05"]["short_description"])
        p2_findings.append(_make_finding("SV-P2-05", entry.get("file"), entry.get("line"), msg))

    # --- SV-P2-07: Frontmatter file_names mismatch ---
    for entry in _iter_list(report.get("frontmatter_file_names_issues", [])):
        if isinstance(entry, dict):
            msg = _extract_item_message(entry, RULES["SV-P2-07"]["short_description"])
            p2_findings.append(_make_finding("SV-P2-07", entry.get("file", "SKILL.md"), entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            p2_findings.append(_make_finding("SV-P2-07", "SKILL.md", None, entry))

    # --- SV-P2-08: Bytecode / junk files ---
    for entry in _iter_list(report.get("junk_files", [])):
        if isinstance(entry, dict):
            fpath = entry.get("file") or entry.get("path") or "."
            msg = _extract_item_message(entry, f"Bytecode-/Junk-Datei vorhanden: `{_normalize_file(fpath, default='.')}`.")
            p2_findings.append(_make_finding("SV-P2-08", fpath, entry.get("line"), msg, default_file="."))
        elif isinstance(entry, str) and entry.strip():
            norm = _normalize_file(entry, default=".")
            p2_findings.append(
                _make_finding(
                    "SV-P2-08",
                    norm,
                    None,
                    f"Bytecode-/Junk-Datei vorhanden: `{norm}`.",
                    default_file=".",
                )
            )

    # --- SV-P2-09 (spec error) & SV-P3-05 (spec advisory) ---
    for entry in _collect_spec_items(report, fm):
        if isinstance(entry, dict):
            rule_id = _classify_spec_rule(entry)
            fpath = entry.get("file", "SKILL.md")
            line = entry.get("line")
            msg = _extract_item_message(entry, RULES[rule_id]["short_description"])
            finding = _make_finding(rule_id, fpath, line, msg)
        elif isinstance(entry, str) and entry.strip():
            lower = entry.lower()
            rule_id = (
                "SV-P2-09"
                if any(k in lower for k in _P2_SPEC_KINDS)
                else "SV-P3-05"
            )
            finding = _make_finding(rule_id, "SKILL.md", None, entry)
        else:
            continue

        if finding["priority"] == "P2":
            p2_findings.append(finding)
        else:
            p3_findings.append(finding)

    # --- SV-P2-12: Process lifecycle / orphan process risks ---
    for entry in _iter_list(report.get("process_lifecycle_issues", [])):
        if isinstance(entry, dict):
            conf = str(entry.get("confidence", "")).strip() or None
            msg = _extract_item_message(entry, RULES["SV-P2-12"]["short_description"])
            p2_findings.append(
                _make_finding("SV-P2-12", entry.get("file", "SKILL.md"), entry.get("line"), msg, confidence=conf)
            )
        elif isinstance(entry, str) and entry.strip():
            p2_findings.append(_make_finding("SV-P2-12", "SKILL.md", None, entry))

    # --- SV-P3-01 & SV-P3-02: SKILL.md frontmatter description & EN trigger ---
    if fm.get("exists"):
        if not fm.get("description_within_1024", True):
            desc_len = fm.get("description_len")
            if isinstance(desc_len, int) and desc_len > 1024:
                msg = f"SKILL.md description überschreitet das 1024-Zeichen-Limit ({desc_len} Zeichen)."
            elif desc_len == 0:
                msg = "SKILL.md description fehlt oder ist leer (0 Zeichen)."
            else:
                msg = "SKILL.md description fehlt oder überschreitet 1024 Zeichen."
            p3_findings.append(_make_finding("SV-P3-01", "SKILL.md", None, msg))
        if not fm.get("bilingual_en_trigger", True):
            p3_findings.append(
                _make_finding(
                    "SV-P3-02",
                    "SKILL.md",
                    None,
                    "Englischer Trigger in SKILL.md description fehlt (z. B. 'Use when ...').",
                )
            )

    # --- SV-P3-04: Context budget / TOC warnings ---
    for entry in _iter_list(report.get("budget_warnings", [])):
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            msg = _extract_item_message(entry, RULES["SV-P3-04"]["short_description"])
            p3_findings.append(_make_finding("SV-P3-04", fpath, entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            m = _BACKTICK_FILE_RE.match(entry.strip())
            fpath = m.group(1) if m else "SKILL.md"
            p3_findings.append(_make_finding("SV-P3-04", fpath, None, entry))

    # --- SV-P3-06: Cross-language contamination (contamination.flagged) ---
    contamination = report.get("contamination")
    if isinstance(contamination, dict):
        flagged_val = contamination.get("flagged")
        if flagged_val is True:
            app_fams = [str(f) for f in _iter_list(contamination.get("application_families")) if str(f).strip()]
            if app_fams:
                msg = (
                    f"Cross-Language-Kontamination erkannt: {len(app_fams)} Anwendungssprachfamilien "
                    f"({', '.join(app_fams)}) ohne Multi-Interface-Kontext."
                )
            else:
                msg = _extract_item_message(contamination, RULES["SV-P3-06"]["short_description"])
            p3_findings.append(
                _make_finding("SV-P3-06", contamination.get("file", "SKILL.md"), contamination.get("line"), msg)
            )
            flagged_items: list[Any] = []
        else:
            flagged_items = _iter_list(flagged_val)
    elif isinstance(contamination, list):
        flagged_items = contamination
    else:
        flagged_items = []
    for entry in flagged_items:
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            line = entry.get("line")
            default_msg = RULES["SV-P3-06"]["short_description"]
            ratio = entry.get("ratio", entry.get("foreign_ratio"))
            if isinstance(ratio, (int, float)) and not any(
                isinstance(entry.get(k), str) and str(entry.get(k)).strip()
                for k in ("message", "detail", "reason", "description")
            ):
                pct = f"{ratio * 100:.1f}%" if 0 <= ratio <= 1 else f"{ratio:.1f}%"
                msg = f"Sprachkontamination in `{_normalize_file(fpath)}` (Fremdsprachenanteil: {pct})."
            else:
                msg = _extract_item_message(entry, default_msg)
            p3_findings.append(_make_finding("SV-P3-06", fpath, line, msg))
        elif isinstance(entry, str) and entry.strip():
            p3_findings.append(
                _make_finding(
                    "SV-P3-06",
                    entry if "/" in entry or entry.endswith(".md") else "SKILL.md",
                    None,
                    f"Sprachkontamination erkannt: {entry}",
                )
            )

    # --- SV-P3-07: Prose / workflow issues in SKILL.md ---
    for entry in _iter_list(report.get("prose_workflow_issues", [])):
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            msg = _extract_item_message(entry, RULES["SV-P3-07"]["short_description"])
            p3_findings.append(_make_finding("SV-P3-07", fpath, entry.get("line"), msg))
        elif isinstance(entry, str) and entry.strip():
            p3_findings.append(_make_finding("SV-P3-07", "SKILL.md", None, entry))

    # --- SV-P3-08: Eval quality advisories ---
    for entry in _iter_list(report.get("evals_quality_issues", [])):
        if isinstance(entry, dict):
            fpath = entry.get("file", "evals/cases.json")
            msg = _extract_item_message(entry, RULES["SV-P3-08"]["short_description"])
            p3_findings.append(
                _make_finding("SV-P3-08", fpath, entry.get("line"), msg, default_file="evals/cases.json")
            )
        elif isinstance(entry, str) and entry.strip():
            p3_findings.append(
                _make_finding("SV-P3-08", "evals/cases.json", None, entry, default_file="evals/cases.json")
            )

    # --- SV-P3-09: Purpose-vs-architecture alignment advisories ---
    purpose_raw = report.get("purpose_issues")
    if purpose_raw is None and isinstance(report.get("purpose"), dict):
        purpose_raw = report["purpose"].get("issues", [])  # type: ignore[union-attr]
    for entry in _iter_list(purpose_raw):
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            msg = _extract_item_message(entry, RULES["SV-P3-09"]["short_description"])
            conf = str(entry.get("confidence", "")).strip() or None
            p3_findings.append(
                _make_finding("SV-P3-09", fpath, entry.get("line"), msg, confidence=conf)
            )
        elif isinstance(entry, str) and entry.strip():
            p3_findings.append(_make_finding("SV-P3-09", "SKILL.md", None, entry))

    # --- SV-P3-10: Version and rule-registry consistency advisories ---
    for entry in _iter_list(report.get("consistency_issues", [])):
        if isinstance(entry, dict):
            fpath = entry.get("file", "SKILL.md")
            msg = _extract_item_message(entry, RULES["SV-P3-10"]["short_description"])
            conf = str(entry.get("confidence", "")).strip() or None
            p3_findings.append(
                _make_finding(
                    "SV-P3-10",
                    fpath,
                    entry.get("line"),
                    msg,
                    default_file="SKILL.md",
                    confidence=conf,
                )
            )
        elif isinstance(entry, str) and entry.strip():
            p3_findings.append(_make_finding("SV-P3-10", "SKILL.md", None, entry, default_file="SKILL.md"))

    return p1_findings + p2_findings + p3_findings


def _to_artifact_uri(file_path: str) -> str:
    """Encodes a relative POSIX path as a valid SARIF artifactLocation.uri."""
    norm = _normalize_file(file_path, default=".")
    return urllib.parse.quote(norm, safe="/:@-._~!$&'()*+,;=")


def render_sarif(report: dict[str, object], tool_version: str = TOOL_VERSION) -> dict[str, object]:
    """Renders an ``audit_directory()`` report dict as a SARIF 2.1.0 dictionary."""
    findings = extract_findings(report)

    rule_ids = sorted(RULES.keys())
    rule_index_map = {rid: idx for idx, rid in enumerate(rule_ids)}

    sarif_rules: list[dict[str, object]] = []
    for rid in rule_ids:
        meta = RULES[rid]
        rule_entry: dict[str, object] = {
            "id": rid,
            "name": meta["name"],
            "shortDescription": {"text": meta["short_description"]},
            "fullDescription": {"text": meta["full_description"]},
            "defaultConfiguration": {"level": meta["level"]},
            "properties": {
                "priority": meta["priority"],
                "category": meta["category"],
                "tags": ["skill-audit", meta["priority"], meta["category"]],
            },
        }
        if meta.get("help_text"):
            rule_entry["help"] = {"text": meta["help_text"]}
        sarif_rules.append(rule_entry)

    sarif_results: list[dict[str, object]] = []
    for finding in findings:
        rid = str(finding["rule_id"])
        level = str(finding["level"])
        message_text = str(finding["message"])
        file_uri = _to_artifact_uri(str(finding["file"]))
        line = _normalize_line(finding.get("line"))
        meta = RULES.get(rid, {})

        physical_location: dict[str, object] = {
            "artifactLocation": {"uri": file_uri},
        }
        if line is not None:
            physical_location["region"] = {"startLine": line}

        result_obj: dict[str, object] = {
            "ruleId": rid,
            "level": level,
            "message": {"text": message_text},
            "locations": [{"physicalLocation": physical_location}],
            "properties": {
                "priority": str(finding.get("priority", meta.get("priority", "P3"))),
                "category": str(meta.get("category", "")),
                "confidence": str(finding.get("confidence", "verified")),
            },
        }
        if rid in rule_index_map:
            result_obj["ruleIndex"] = rule_index_map[rid]
        sarif_results.append(result_obj)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": tool_version,
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _build_mock_report() -> dict[str, object]:
    """Builds a comprehensive mock audit report covering every P1, P2, and P3 rule (28 rules)."""
    return {
        "target": "/tmp/mock-skill",
        "mode": "skill-folder",
        "summary": {
            "unclosed_code_blocks": ["SKILL.md"],
        },
        "frontmatter": {
            "exists": True,
            "name": "Bad_Skill_Name",
            "description_len": 1200,
            "description_within_1024": False,
            "bilingual_en_trigger": False,
        },
        "broken_links": [
            {"file": "SKILL.md", "line": 14, "link": "references/missing.md#intro", "reason": "Zieldatei fehlt"},
        ],
        "dead_local_references": [
            {"reference": "scripts/ghost.py", "mentioned_in": ["SKILL.md", "references/guide.md"]},
        ],
        "orphan_files": ["references/unused_notes.md"],
        "format_issues": [
            {"file": "SKILL.md", "line": 22, "kind": "trailing-whitespace", "snippet": "'Zeile   '"},
        ],
        "mermaid_issues": [
            {
                "file": "references/guide.md",
                "line": 31,
                "kind": "mermaid-unquoted-label",
                "snippet": "A[Start (v1)] -> bitte in Anführungszeichen setzen",
            },
        ],
        "portability_and_sandbox_issues": [
            {"file": "SKILL.md", "line": 40, "kind": "sandbox-anti-pattern", "snippet": "sudo apt-get install jq"},
            {"file": "SKILL.md", "line": 45, "kind": "hardcoded-platform-path", "snippet": "~/.gemini/skills/demo"},
        ],
        "evals_issues": [
            "evals/cases.json: Ungültiges JSON (Expecting value: line 1 column 1)",
            "evals/cases.json (c1): Pflichtfeld 'must_contain' fehlt",
        ],
        "frontmatter_file_names_issues": [
            "Frontmatter `file_names`-Eintrag fehlt im Ordner: `scripts/missing.py`",
        ],
        "junk_files": ["scripts/__pycache__/helper.cpython-312.pyc"],
        "budget_warnings": [
            "`references/guide.md` hat ~18,000 Tokens ohne Inhaltsverzeichnis (TOC empfohlen).",
        ],
        "security_issues": [
            {
                "file": "SKILL.md",
                "line": 8,
                "severity": "p1",
                "kind": "unicode-bidi-override",
                "codepoint": "U+202E",
                "name": "RIGHT-TO-LEFT OVERRIDE",
                "snippet": "text\\u202ehidden",
            },
            {
                "file": "scripts/run.py",
                "line": 17,
                "severity": "p1",
                "kind": "script-code-exec",
                "message": "Dynamische Code-Ausführung via `eval()`",
                "snippet": "eval(user_input)",
            },
            {
                "file": "scripts/run.py",
                "line": 3,
                "severity": "p1",
                "kind": "hardcoded-secret",
                "message": "Mögliches hardcoded Secret erkannt (OpenAI API Key)",
                "snippet": "KEY = 'sk-***'",
            },
            {
                "file": "SKILL.md",
                "line": 12,
                "severity": "p2",
                "kind": "unicode-zero-width",
                "codepoint": "U+200B",
                "name": "ZERO WIDTH SPACE",
                "snippet": "zero\\u200bwidth",
            },
            {
                "file": "scripts/run.py",
                "line": 25,
                "severity": "p2",
                "kind": "script-unsafe-deserialize",
                "message": "Unsichere Deserialisierung via `pickle.loads()`",
                "snippet": "pickle.loads(data)",
            },
        ],
        "spec_issues": [
            {
                "file": "SKILL.md",
                "line": 2,
                "severity": "p2",
                "kind": "spec-invalid-name",
                "message": "Frontmatter `name` verletzt agentskills.io-Regeln: Uppercase nicht erlaubt.",
            },
            {
                "file": "SKILL.md",
                "line": 6,
                "severity": "p3",
                "kind": "spec-nonstandard-field",
                "message": "Unbekanntes Frontmatter-Feld `author`.",
            },
        ],
        "contamination": {
            "application_families": ["go", "python", "rust"],
            "auxiliary_families": ["shell"],
            "multi_interface_context": False,
            "flagged": True,
            "matched_multi_interface_tools": [],
        },
        "prose_workflow_issues": [
            {
                "line": 50,
                "heading": "## Installation",
                "severity": "p3",
                "kind": "readme-tier-in-skill",
                "message": "README-Tier-Überschrift `## Installation` in `SKILL.md` (Zeile 50).",
            },
        ],
        "evals_quality_issues": [
            {
                "severity": "p3",
                "kind": "eval-no-negative-case",
                "case_count": 3,
                "message": "`cases.json` enthält 3 Testfälle, aber keinen Negative-Trigger-Fall.",
            },
        ],
        "purpose_issues": [
            {
                "file": "SKILL.md",
                "severity": "p3",
                "kind": "purpose-missing-negative-boundary",
                "confidence": "heuristic",
                "message": "`SKILL.md`-`description` fehlt eine explizite Negativ-Abgrenzung (`Don't use`).",
            },
        ],
        "consistency_issues": [
            {
                "file": "evals/cases.json",
                "severity": "p3",
                "kind": "version-mismatch-evals",
                "confidence": "verified",
                "message": "Version in evals/cases.json (1.4-DE) weicht von SKILL.md (1.5-DE) ab.",
            },
        ],
        "process_lifecycle_issues": [
            {
                "file": "scripts/server.py",
                "line": 42,
                "severity": "p2",
                "kind": "unmanaged-popen",
                "confidence": "verified",
                "message": "subprocess.Popen ohne Lifecycle-Cleanup (with/atexit/signal + terminate/kill).",
            },
        ],
    }


def run_self_test() -> int:
    """Runs comprehensive self-tests for RULES, extract_findings, check_version_and_rule_consistency, and render_sarif."""
    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    # 1. Rule catalog integrity (28 rules: SV-P1-01..06, SV-P2-01..12, SV-P3-01..10)
    expected_rule_ids = {
        *(f"SV-P1-0{i}" for i in range(1, 7)),
        *(f"SV-P2-{i:02d}" for i in range(1, 13)),
        *(f"SV-P3-{i:02d}" for i in range(1, 11)),
    }
    check(len(RULES) == RULE_COUNT == 28, f"Expected RULE_COUNT=28, got len(RULES)={len(RULES)}")
    check(set(RULES.keys()) == expected_rule_ids, f"RULES keys mismatch: {set(RULES.keys()) ^ expected_rule_ids}")
    for rid, meta in RULES.items():
        check(meta["priority"] in {"P1", "P2", "P3"}, f"{rid}: invalid priority {meta['priority']}")
        expected_level = {"P1": "error", "P2": "warning", "P3": "note"}[meta["priority"]]
        check(meta["level"] == expected_level, f"{rid}: expected level {expected_level}, got {meta['level']}")
        check(all(isinstance(v, str) and v for v in meta.values()), f"{rid}: all metadata values must be non-empty str")

    # 2. v1.3 graceful empty / minimal report compatibility (and contamination.flagged=False)
    empty_findings = extract_findings({})
    check(empty_findings == [], f"Empty report should yield [], got {empty_findings}")
    minimal_v13 = {
        "summary": {"unclosed_code_blocks": []},
        "frontmatter": {"exists": True, "description_within_1024": True, "bilingual_en_trigger": True},
        "broken_links": [],
        "dead_local_references": [],
        "format_issues": [],
        "mermaid_issues": [],
        "portability_and_sandbox_issues": [],
        "evals_issues": [],
        "frontmatter_file_names_issues": [],
        "junk_files": [],
        "budget_warnings": [],
        "contamination": {"application_families": ["python"], "flagged": False},
    }
    check(extract_findings(minimal_v13) == [], "Clean v1.3/v1.4/v1.5 report should yield 0 findings")

    # 3. Full mock report covering all 28 rules (P1, P2, P3)
    mock_report = _build_mock_report()
    findings = extract_findings(mock_report)
    found_ids = {str(f["rule_id"]) for f in findings}
    check(
        found_ids == expected_rule_ids,
        f"Mock report did not cover all rules; missing={expected_rule_ids - found_ids}, extra={found_ids - expected_rule_ids}",
    )

    required_finding_keys = {"rule_id", "priority", "level", "file", "line", "message"}
    allowed_finding_keys = required_finding_keys | {"confidence"}
    for f in findings:
        check(
            required_finding_keys.issubset(f.keys()) and set(f.keys()).issubset(allowed_finding_keys),
            f"Unexpected finding keys: {f.keys()}",
        )
        check(f["priority"] in {"P1", "P2", "P3"}, f"Invalid priority in finding: {f}")
        check(f["level"] in {"error", "warning", "note"}, f"Invalid level in finding: {f}")
        check(isinstance(f["file"], str) and len(f["file"]) > 0, f"Invalid file in finding: {f}")
        check(
            f["line"] is None or (isinstance(f["line"], int) and not isinstance(f["line"], bool) and f["line"] > 0),
            f"Invalid line in finding: {f}",
        )
        check(isinstance(f["message"], str) and len(f["message"]) > 0, f"Empty message in finding: {f}")
        if "confidence" in f:
            check(f["confidence"] in {"verified", "heuristic"}, f"Invalid confidence in finding: {f}")

    # 4. SARIF 2.1.0 structure & JSON round-trip validation
    sarif = render_sarif(mock_report)
    serialized = json.dumps(sarif, ensure_ascii=False, indent=2)
    parsed = json.loads(serialized)

    check(parsed.get("$schema") == SARIF_SCHEMA_URI, "Missing or invalid $schema")
    check(parsed.get("version") == "2.1.0", "SARIF version must be 2.1.0")
    runs = parsed.get("runs")
    check(isinstance(runs, list) and len(runs) == 1, "SARIF must contain exactly 1 run")
    run = runs[0]
    driver = run["tool"]["driver"]
    check(driver["name"] == TOOL_NAME, f"Unexpected driver name: {driver['name']}")
    check(driver["version"] == TOOL_VERSION, f"Unexpected driver version: {driver['version']} (expected {TOOL_VERSION})")
    check(bool(driver.get("informationUri")), "Missing driver.informationUri")

    sarif_rules = driver["rules"]
    check(len(sarif_rules) == len(RULES), f"Expected {len(RULES)} SARIF rules, got {len(sarif_rules)}")
    rule_id_set = {r["id"] for r in sarif_rules}
    check(rule_id_set == expected_rule_ids, "SARIF rules do not match RULES catalog")

    results = run["results"]
    check(len(results) == len(findings), f"Result count mismatch: {len(results)} vs {len(findings)}")
    has_with_region = False
    has_without_region = False
    for res in results:
        check(res["ruleId"] in rule_id_set, f"Unknown result ruleId: {res['ruleId']}")
        check(res["level"] in {"error", "warning", "note"}, f"Invalid SARIF level: {res['level']}")
        check(isinstance(res["message"]["text"], str) and res["message"]["text"], "Empty SARIF message.text")
        props = res.get("properties", {})
        check(props.get("confidence") in {"verified", "heuristic"}, f"Missing or invalid result confidence: {props}")
        locs = res["locations"]
        check(isinstance(locs, list) and len(locs) == 1, "Result must have 1 location")
        phys = locs[0]["physicalLocation"]
        uri = phys["artifactLocation"]["uri"]
        check(isinstance(uri, str) and len(uri) > 0, "Empty artifactLocation.uri")
        if "region" in phys:
            has_with_region = True
            start_line = phys["region"].get("startLine")
            check(
                isinstance(start_line, int) and not isinstance(start_line, bool) and start_line > 0,
                f"Invalid region.startLine: {start_line}",
            )
        else:
            has_without_region = True

    check(has_with_region, "Expected at least one result with region.startLine")
    check(has_without_region, "Expected at least one file-level result without region")

    # Verify non-positive line numbers never emit a region
    zero_line_sarif = render_sarif(
        {"broken_links": [{"file": "SKILL.md", "line": 0, "link": "#x", "reason": "missing"}]}
    )
    zero_phys = zero_line_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    check("region" not in zero_phys, "line=0 must not produce a SARIF region")

    # 5. Test check_version_and_rule_consistency on matching & mismatched temporary directories
    with tempfile.TemporaryDirectory() as tmpdir_ok:
        ok_root = Path(tmpdir_ok)
        (ok_root / "evals").mkdir()
        (ok_root / "references").mkdir()
        (ok_root / "evals" / "cases.json").write_text(
            json.dumps({"version": TOOL_VERSION, "cases": []}), encoding="utf-8"
        )
        (ok_root / "CHANGELOG.md").write_text(f"# Changelog\n\n## [{TOOL_VERSION}]\n", encoding="utf-8")
        (ok_root / "README.md").write_text(f"# Skill ({TOOL_VERSION})\n", encoding="utf-8")
        all_rules_str = " ".join(sorted(RULES.keys()))
        (ok_root / "references" / "PRUEFKATALOG.md").write_text(
            f"# Prüfkatalog ({TOOL_VERSION}) — {len(RULES)} Regeln\n{all_rules_str}\n",
            encoding="utf-8",
        )
        ok_issues = check_version_and_rule_consistency(
            ok_root, {"name": "skill-verbesserungsanalyse", "version": TOOL_VERSION}
        )
        check(ok_issues == [], f"Expected 0 consistency issues on matching dir, got {ok_issues}")

    with tempfile.TemporaryDirectory() as tmpdir_bad:
        bad_root = Path(tmpdir_bad)
        (bad_root / "evals").mkdir()
        (bad_root / "references").mkdir()
        (bad_root / "evals" / "cases.json").write_text(
            json.dumps({"version": "1.2-DE", "cases": []}), encoding="utf-8"
        )
        (bad_root / "CHANGELOG.md").write_text("# Changelog\n\n## [1.0-DE]\n", encoding="utf-8")
        (bad_root / "README.md").write_text("# Skill (1.3-DE)\n", encoding="utf-8")
        (bad_root / "references" / "PRUEFKATALOG.md").write_text(
            "# Prüfkatalog (1.3-DE) — 25 Regeln\nSV-P1-01\n", encoding="utf-8"
        )
        bad_issues = check_version_and_rule_consistency(
            bad_root, {"name": "skill-verbesserungsanalyse", "version": "1.4-DE"}
        )
        bad_kinds = {str(item.get("kind")) for item in bad_issues}
        expected_bad_kinds = {
            "version-mismatch-evals",
            "version-missing-in-changelog",
            "version-mismatch-ssot",
            "version-drift-doc",
            "rule-registry-drift-doc",
        }
        check(
            expected_bad_kinds.issubset(bad_kinds),
            f"Expected consistency issue kinds {expected_bad_kinds}, got {bad_kinds}",
        )

    if failures:
        print(f"SELF-TEST FEHLGESCHLAGEN ({len(failures)} Fehler):", file=sys.stderr)
        for fail in failures:
            print(f"  - {fail}", file=sys.stderr)
        return 1

    print(
        f"SELF-TEST BESTANDEN: {len(RULES)} Regeln, {len(findings)} Befunde (P1/P2/P3), "
        f"SARIF 2.1.0 valide ({len(serialized)} Bytes JSON)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Konvertiert einen skill_audit.py JSON-Report in SARIF 2.1.0 oder führt den Selbsttest aus."
    )
    parser.add_argument(
        "report_json",
        nargs="?",
        help="Pfad zu einer JSON-Report-Datei (oder '-' für stdin).",
    )
    parser.add_argument(
        "--tool-version",
        default=TOOL_VERSION,
        help=f"Tool-Version für SARIF tool.driver.version (Standard: {TOOL_VERSION}).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optionale Ausgabedatei für SARIF JSON (Standard: stdout).",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Führt den internen Selbsttest aus.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not args.report_json:
        parser.error("Bitte entweder <report_json> angeben oder --self-test ausführen.")

    if args.report_json == "-":
        raw_text = sys.stdin.read()
    else:
        raw_text = Path(args.report_json).read_text(encoding="utf-8")

    report = json.loads(raw_text)
    sarif = render_sarif(report, tool_version=args.tool_version)
    output_text = json.dumps(sarif, ensure_ascii=False, indent=2) + "\n"

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
    else:
        sys.stdout.write(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
