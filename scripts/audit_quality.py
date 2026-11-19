#!/usr/bin/env python3
"""Eigenständiges Qualitäts-Audit-Modul für KI-Skills (Zero-Dependency, Python 3.10+ Stdlib).

Prüft:
1. Verwaiste Dateien (Orphan Files) via BFS-Erreichbarkeit ab SKILL.md (inkl. transitiver Python-Imports)
2. agentskills.io-Frontmatter-Spezifikation (NFKC-Name, Verzeichnisabgleich, compatibility, Standardfelder)
3. Sprach-Kontaminations-Analyse (Application- vs. Auxiliary-Familien & Multi-Interface-Kontext)
4. SKILL.md-Prosa & Workflow-Qualität (README-Tier-Überschriften, fehlende Verifikations-/Stopp-Gates)
5. Eval-Qualität (Negative-Trigger-Abdeckung & Prompt-Leakage in evals/cases.json)

Nutzung:
  PYTHONDONTWRITEBYTECODE=1 python3 scripts/audit_quality.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import pathlib
import re
import sys
import tempfile
import unicodedata
import urllib.parse

sys.dont_write_bytecode = True

ORPHAN_INVENTORY_DIRS = ("scripts", "references", "assets")
JUNK_DIR_NAMES = {"__pycache__"}
JUNK_SUFFIXES = {".pyc", ".pyo"}

AGENTSKILLS_STANDARD_FIELDS = frozenset(
    {
        "name",
        "description",
        "license",
        "allowed-tools",
        "metadata",
        "compatibility",
    }
)

APP_LANGUAGE_FAMILIES: dict[str, str] = {
    # python
    "python": "python",
    "py": "python",
    "python3": "python",
    "py3": "python",
    "pyi": "python",
    "cython": "python",
    # javascript / typescript
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "javascript",
    "ts": "javascript",
    "jsx": "javascript",
    "tsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    # java / jvm
    "java": "java",
    "kotlin": "java",
    "kt": "java",
    "kts": "java",
    "scala": "java",
    "groovy": "java",
    # systems
    "c": "systems",
    "cpp": "systems",
    "c++": "systems",
    "cc": "systems",
    "cxx": "systems",
    "h": "systems",
    "hpp": "systems",
    "rust": "systems",
    "rs": "systems",
    "go": "systems",
    "golang": "systems",
    "zig": "systems",
    "asm": "systems",
    "assembly": "systems",
    # ruby
    "ruby": "ruby",
    "rb": "ruby",
    "erb": "ruby",
    # dotnet
    "csharp": "dotnet",
    "c#": "dotnet",
    "cs": "dotnet",
    "fsharp": "dotnet",
    "f#": "dotnet",
    "fs": "dotnet",
    "vb": "dotnet",
    "vbnet": "dotnet",
    "dotnet": "dotnet",
    # mobile
    "swift": "mobile",
    "objc": "mobile",
    "objective-c": "mobile",
    "objectivec": "mobile",
    "dart": "mobile",
}

AUX_LANGUAGE_FAMILIES: dict[str, str] = {
    # shell
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "shell": "shell",
    "console": "shell",
    "fish": "shell",
    "powershell": "shell",
    "ps1": "shell",
    "pwsh": "shell",
    "bat": "shell",
    "cmd": "shell",
    "dos": "shell",
    "shellsession": "shell",
    # config
    "yaml": "config",
    "yml": "config",
    "json": "config",
    "jsonc": "config",
    "json5": "config",
    "toml": "config",
    "ini": "config",
    "cfg": "config",
    "conf": "config",
    "env": "config",
    "dotenv": "config",
    "hcl": "config",
    "tf": "config",
    "terraform": "config",
    "dockerfile": "config",
    "docker": "config",
    "nginx": "config",
    "properties": "config",
    "editorconfig": "config",
    "makefile": "config",
    "make": "config",
    "cmake": "config",
    # query
    "sql": "query",
    "postgresql": "query",
    "postgres": "query",
    "psql": "query",
    "mysql": "query",
    "sqlite": "query",
    "tsql": "query",
    "plsql": "query",
    "graphql": "query",
    "gql": "query",
    "cypher": "query",
    "sparql": "query",
    "promql": "query",
    "jq": "query",
    "regex": "query",
    # markup
    "html": "markup",
    "htm": "markup",
    "xml": "markup",
    "xhtml": "markup",
    "svg": "markup",
    "css": "markup",
    "scss": "markup",
    "sass": "markup",
    "less": "markup",
    "markdown": "markup",
    "md": "markup",
    "rst": "markup",
    "tex": "markup",
    "latex": "markup",
    "mermaid": "markup",
    "text": "markup",
    "txt": "markup",
    "plain": "markup",
    "plaintext": "markup",
    "diff": "markup",
    "patch": "markup",
    "csv": "markup",
    "tsv": "markup",
    "proto": "markup",
    "protobuf": "markup",
}

MULTI_INTERFACE_TOOLS = (
    "docker",
    "kubernetes",
    "aws",
    "mongodb",
    "postgresql",
    "mysql",
    "redis",
    "graphql",
    "grpc",
    "terraform",
    "stripe",
    "firebase",
    "kafka",
)

MULTI_INTERFACE_TOOL_ALIASES: dict[str, str] = {
    **{tool: tool for tool in MULTI_INTERFACE_TOOLS},
    "k8s": "kubernetes",
    "postgres": "postgresql",
}

MULTI_INTERFACE_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(MULTI_INTERFACE_TOOL_ALIASES, key=len, reverse=True)) + r")\b",
    re.I,
)

README_TIER_HEADING_RE = re.compile(
    r"^#{1,3}\s+(Installation|Install|License|Lizenz|Contributing|Changelog)\b",
    re.I,
)

STEP_PHASE_HEADING_RE = re.compile(
    r"^#{1,4}\s+(?:Step|Phase|Schritt)\s+\d+\b",
    re.I,
)

VERIFICATION_GATE_CUE_RE = re.compile(
    r"(?:"
    r"verifiz|"
    r"\bverif(?:y|ied|ies|ication)\b|"
    r"\bconfirm|"
    r"bestätig|"
    r"\bcheck|"
    r"prüf|"
    r"\bexit\b|"
    r"\bnur\s+nach\b|"
    r"\berst\s+bei\b|"
    r"\bproceed\s+only\b|"
    r"\babbrechen\b|"
    r"\bfallback\b|"
    r"stopp|"
    r"\babort\b|"
    r"\bfreigabe\b|"
    r"\bvalidat"
    r")",
    re.I,
)

PY_IMPORT_FALLBACK_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\s+([^\n#]+)|import\s+([^\n#]+))",
    re.M,
)

NEGATIVE_ID_MARKERS = ("negative", "out-of-scope", "out_of_scope", "no-trigger", "no_trigger")


def _extract_python_imported_stems(py_text: str) -> set[str]:
    """Extrahiert potenzielle lokale Modul-Stems aus Python-Import-Anweisungen."""
    stems: set[str] = set()
    try:
        tree = ast.parse(py_text)
    except SyntaxError:
        for m in PY_IMPORT_FALLBACK_RE.finditer(py_text):
            mod, from_names, imp_names = m.group(1), m.group(2), m.group(3)
            if mod:
                parts = [p for p in mod.split(".") if p]
                if parts:
                    stems.add(parts[-1])
            if from_names:
                for raw in from_names.replace("(", "").replace(")", "").split(","):
                    tok = raw.strip().split(" as ")[0].strip()
                    if tok and tok != "*":
                        stems.add(tok)
            if imp_names:
                for raw in imp_names.split(","):
                    tok = raw.strip().split(" as ")[0].strip()
                    parts = [p for p in tok.split(".") if p]
                    if parts:
                        stems.add(parts[-1])
        return stems

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = [p for p in alias.name.split(".") if p]
                if parts:
                    stems.add(parts[-1])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                parts = [p for p in node.module.split(".") if p]
                if parts:
                    stems.add(parts[-1])
            for alias in node.names:
                if alias.name and alias.name != "*":
                    stems.add(alias.name)
    return stems


def _is_file_referenced(
    cand: str,
    cur_file: str,
    cur_text: str,
    cur_text_unquoted: str,
    imported_stems: set[str],
    basename_patterns: dict[str, re.Pattern[str]],
) -> bool:
    """Prüft, ob `cand` im Text (oder über Python-Imports) von `cur_file` referenziert wird."""
    if cand in cur_text or cand in cur_text_unquoted:
        return True

    pat = basename_patterns[cand]
    if pat.search(cur_text) or pat.search(cur_text_unquoted):
        return True

    if cur_file.endswith(".py") and cand.endswith(".py"):
        stem = pathlib.PurePosixPath(cand).stem
        if stem in imported_stems:
            return True

    return False


def _strip_frontmatter_and_fences_preserve_lines(text: str) -> list[str]:
    """Ersetzt Frontmatter- und Fenced-Code-Zeilen durch Leerzeilen (Zeilennummern bleiben 1:1 erhalten)."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    start_idx = 0
    if lines and lines[0] == "---":
        for idx in range(1, len(lines)):
            if lines[idx] == "---":
                start_idx = idx + 1
                break

    out: list[str] = [""] * start_idx
    in_fence = False
    fence_char = ""
    fence_len = 0

    for line in lines[start_idx:]:
        m = re.match(r"^\s*(`{3,}|~{3,})", line)
        if m:
            marker = m.group(1)
            rest = line[m.end() :]
            is_inline_backtick = marker[0] == "`" and "`" in rest
            if not in_fence:
                if is_inline_backtick:
                    out.append(line)
                    continue
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                out.append("")
                continue
            if marker[0] == fence_char and len(marker) >= fence_len and rest.strip() == "":
                in_fence = False
                fence_char = ""
                fence_len = 0
                out.append("")
                continue
            out.append("")
            continue
        out.append("" if in_fence else line)

    return out


def find_orphan_files(
    target: pathlib.Path,
    all_files: set[str],
    md_texts: dict[str, str],
) -> list[dict[str, object]]:
    """Findet verwaiste Dateien unter scripts/, references/ und assets/ via BFS ab SKILL.md."""
    if "SKILL.md" not in all_files:
        return []

    inventory_files: list[str] = []
    root_md_files: list[str] = []

    for rel in sorted(all_files):
        posix_rel = rel.replace("\\", "/")
        parts = pathlib.PurePosixPath(posix_rel).parts
        if not parts:
            continue
        if any(p.startswith(".") for p in parts):
            continue
        if any(p in JUNK_DIR_NAMES for p in parts):
            continue
        if pathlib.PurePosixPath(posix_rel).suffix.lower() in JUNK_SUFFIXES:
            continue

        if len(parts) >= 2 and parts[0] in ORPHAN_INVENTORY_DIRS:
            if parts[-1] == "__init__.py":
                continue
            inventory_files.append(posix_rel)
        elif len(parts) == 1 and posix_rel.lower().endswith(".md") and posix_rel != "SKILL.md":
            root_md_files.append(posix_rel)

    if not inventory_files:
        return []

    candidates = inventory_files + root_md_files
    basename_patterns: dict[str, re.Pattern[str]] = {}
    for cand in candidates:
        base = pathlib.PurePosixPath(cand).name
        basename_patterns[cand] = re.compile(
            rf"(?<![A-Za-z0-9_.-]){re.escape(base)}(?![A-Za-z0-9_]|\.[A-Za-z0-9_])"
        )

    def read_node_text(rel_path: str) -> str:
        if rel_path in md_texts:
            return md_texts[rel_path]
        disk_path = target / rel_path
        if disk_path.is_file():
            return disk_path.read_text(encoding="utf-8", errors="replace")
        return ""

    reached: set[str] = {"SKILL.md"}
    queue: collections.deque[str] = collections.deque(["SKILL.md"])

    while queue:
        cur = queue.popleft()
        cur_text = read_node_text(cur)
        if not cur_text:
            continue
        cur_text_unquoted = urllib.parse.unquote(cur_text)
        imported_stems = _extract_python_imported_stems(cur_text) if cur.endswith(".py") else set()

        for cand in candidates:
            if cand in reached:
                continue
            if _is_file_referenced(
                cand,
                cur,
                cur_text,
                cur_text_unquoted,
                imported_stems,
                basename_patterns,
            ):
                reached.add(cand)
                if cand.lower().endswith((".md", ".py")):
                    queue.append(cand)

    orphans: list[dict[str, object]] = []
    for rel in sorted(inventory_files):
        if rel not in reached:
            top_dir = pathlib.PurePosixPath(rel).parts[0]
            orphans.append(
                {
                    "file": rel,
                    "directory": top_dir,
                    "severity": "p2",
                    "kind": "orphan-file",
                    "message": (
                        f"Verwaiste Datei `{rel}` in `{top_dir}/`: weder direkt in `SKILL.md` "
                        "noch transitiv über referenzierte Dateien eingebunden."
                    ),
                }
            )
    return orphans


def validate_agentskills_spec(
    fm: dict[str, object],
    target: pathlib.Path,
) -> list[dict[str, object]]:
    """Validiert SKILL.md-Frontmatter gegen die agentskills.io-Spezifikation (NFKC)."""
    findings: list[dict[str, object]] = []

    raw_name = fm.get("name")
    normalized_name: str | None = None
    name_reasons: list[str] = []

    if not isinstance(raw_name, str) or not raw_name:
        name_reasons.append("fehlt oder ist kein nicht-leerer String")
    else:
        normalized_name = unicodedata.normalize("NFKC", raw_name)
        if len(normalized_name) == 0:
            name_reasons.append("darf nicht leer sein")
        if len(normalized_name) > 64:
            name_reasons.append(f"zu lang ({len(normalized_name)} > 64 Unicode-Codepoints)")
        if normalized_name != normalized_name.lower():
            name_reasons.append("muss vollständig kleingeschrieben sein")
        if normalized_name.startswith("-") or normalized_name.endswith("-"):
            name_reasons.append("darf nicht mit `-` beginnen oder enden")
        if "--" in normalized_name:
            name_reasons.append("darf keine doppelten Bindestriche (`--`) enthalten")
        if not all(ch.isalnum() or ch == "-" for ch in normalized_name):
            name_reasons.append("darf nur alphanumerische Zeichen und `-` enthalten")

    if name_reasons:
        findings.append(
            {
                "severity": "p2",
                "kind": "spec-invalid-name",
                "field": "name",
                "message": f"Frontmatter `name` verletzt agentskills.io-Regeln: {', '.join(name_reasons)}.",
            }
        )

    if normalized_name:
        dir_name = target.name if target.name else target.resolve().name
        if dir_name and not dir_name.startswith("tmp"):
            norm_dir = unicodedata.normalize("NFKC", dir_name)
            if norm_dir != normalized_name:
                findings.append(
                    {
                        "severity": "p3",
                        "kind": "spec-name-dir-mismatch",
                        "field": "name",
                        "message": (
                            f"Frontmatter `name` (`{normalized_name}`) weicht vom "
                            f"Ordnernamen (`{norm_dir}`) ab."
                        ),
                    }
                )

    if "compatibility" in fm:
        compat = fm["compatibility"]
        if not isinstance(compat, str) or len(compat) > 500:
            detail = (
                f"Typ `{type(compat).__name__}` statt `str`"
                if not isinstance(compat, str)
                else f"Länge {len(compat)} > 500 Zeichen"
            )
            findings.append(
                {
                    "severity": "p2",
                    "kind": "spec-invalid-compatibility",
                    "field": "compatibility",
                    "message": f"Frontmatter `compatibility` ist ungültig ({detail}).",
                }
            )

    for key in sorted(fm.keys()):
        if key not in AGENTSKILLS_STANDARD_FIELDS:
            findings.append(
                {
                    "severity": "p3",
                    "kind": "spec-nonstandard-field",
                    "field": key,
                    "message": (
                        f"Nicht-Standard-Frontmatter-Feld `{key}` (außerhalb der "
                        "agentskills.io-Kernfelder; ggf. für Cross-Platform-Publishing unter `metadata` ablegen)."
                    ),
                }
            )

    return findings


def analyze_contamination(
    skill_name: str,
    text: str,
    code_langs: list[str],
) -> dict[str, object]:
    """Analysiert Sprachfamilien in Codeblöcken und erkennt potenzielle Cross-Language-Kontamination."""
    app_fams: set[str] = set()
    aux_fams: set[str] = set()

    for raw_lang in code_langs:
        if not isinstance(raw_lang, str):
            continue
        cleaned = raw_lang.strip().lower()
        if not cleaned:
            continue
        token = cleaned.split()[0].lstrip(".")
        if token in APP_LANGUAGE_FAMILIES:
            app_fams.add(APP_LANGUAGE_FAMILIES[token])
        elif token in AUX_LANGUAGE_FAMILIES:
            aux_fams.add(AUX_LANGUAGE_FAMILIES[token])

    normalized_name = re.sub(r"[_-]+", " ", skill_name or "")
    combined = f"{normalized_name}\n{text or ''}"
    matched_tools = {
        MULTI_INTERFACE_TOOL_ALIASES[m.group(1).lower()]
        for m in MULTI_INTERFACE_RE.finditer(combined)
    }
    multi_interface_context = bool(matched_tools)
    sorted_app = sorted(app_fams)
    sorted_aux = sorted(aux_fams)
    flagged = len(sorted_app) >= 3 and not multi_interface_context

    return {
        "application_families": sorted_app,
        "auxiliary_families": sorted_aux,
        "multi_interface_context": multi_interface_context,
        "flagged": flagged,
        "matched_multi_interface_tools": sorted(matched_tools),
    }


def check_skill_prose_and_workflow(skill_text: str) -> list[dict[str, object]]:
    """Prüft SKILL.md auf README-Tier-Überschriften und fehlende Verifikations-/Exit-Gates bei Workflows."""
    findings: list[dict[str, object]] = []
    prose_lines = _strip_frontmatter_and_fences_preserve_lines(skill_text)

    step_heading_count = 0
    for line_no, line in enumerate(prose_lines, start=1):
        if not line:
            continue
        if README_TIER_HEADING_RE.match(line):
            findings.append(
                {
                    "line": line_no,
                    "heading": line.strip(),
                    "severity": "p3",
                    "kind": "readme-tier-in-skill",
                    "message": (
                        f"README-Tier-Überschrift `{line.strip()}` in `SKILL.md` (Zeile {line_no}) — "
                        "gehört in `README.md` oder `CHANGELOG.md`, um Agenten-Kontext schlank zu halten."
                    ),
                }
            )
        if STEP_PHASE_HEADING_RE.match(line):
            step_heading_count += 1

    if step_heading_count >= 3:
        prose_body = "\n".join(prose_lines)
        if not VERIFICATION_GATE_CUE_RE.search(prose_body):
            findings.append(
                {
                    "severity": "p3",
                    "kind": "workflow-missing-verification",
                    "step_count": step_heading_count,
                    "message": (
                        f"Workflow mit {step_heading_count} Schritt-/Phasen-Überschriften ohne erkennbare "
                        "Verifikations-, Freigabe- oder Stopp-/Fallback-Kriterien."
                    ),
                }
            )

    return findings


_PURPOSE_ADVERSARIAL_EVAL_RE = re.compile(
    r"(?:purpose|zweck|contradiction|widerspruch|claim|adversarial|ghost|clarif|rückfrage|rueckfrage|sv-p3-09)",
    re.I,
)


def _case_tests_purpose_or_adversarial(case: dict[str, object]) -> bool:
    """Prüft, ob ein Eval-Fall Zweck-vor-Architektur-, Widerspruchs- oder Adversarial-Prüfungen abdeckt."""
    blobs: list[str] = [
        str(case.get("id", "")),
        str(case.get("prompt", "")),
    ]
    for key in ("must_contain", "must_not_contain", "must_not_claim", "expected_findings"):
        val = case.get(key)
        if isinstance(val, list):
            blobs.extend(str(x) for x in val)
    rubric = case.get("verification_rubric")
    if isinstance(rubric, list):
        blobs.extend(str(x) for x in rubric)
    elif isinstance(rubric, dict):
        blobs.extend(f"{k}:{v}" for k, v in rubric.items())
    return bool(_PURPOSE_ADVERSARIAL_EVAL_RE.search(" ".join(blobs)))


def has_purpose_or_adversarial_eval_case(cases_path: pathlib.Path) -> bool:
    """Hilfsprüfung, ob evals/cases.json mindestens einen Purpose-/Widerspruchs-/Adversarial-Testfall enthält."""
    if not cases_path.is_file():
        return False
    try:
        raw_data = json.loads(cases_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return False
    raw_cases = raw_data.get("cases") if isinstance(raw_data, dict) else raw_data
    if not isinstance(raw_cases, list):
        return False
    return any(_case_tests_purpose_or_adversarial(c) for c in raw_cases if isinstance(c, dict))


def check_evals_quality(cases_path: pathlib.Path) -> list[dict[str, object]]:
    """Prüft evals/cases.json auf Negative-Trigger-Abdeckung, Prompt-Leakage und v1.5-Rubrik-Felder."""
    if not cases_path.is_file():
        return []
    try:
        raw_data = json.loads(cases_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []

    if isinstance(raw_data, dict):
        raw_cases = raw_data.get("cases")
    elif isinstance(raw_data, list):
        raw_cases = raw_data
    else:
        return []

    if not isinstance(raw_cases, list):
        return []

    cases = [c for c in raw_cases if isinstance(c, dict)]
    if not cases:
        return []

    findings: list[dict[str, object]] = []
    has_purpose_or_adversarial_case = any(_case_tests_purpose_or_adversarial(c) for c in cases)

    if len(cases) >= 3:
        has_negative = False
        for case in cases:
            if case.get("should_trigger") is False:
                has_negative = True
                break
            exp_mods = case.get("expected_modules")
            if isinstance(exp_mods, list) and len(exp_mods) == 0:
                has_negative = True
                break
            case_id_low = str(case.get("id", "")).lower()
            if any(marker in case_id_low for marker in NEGATIVE_ID_MARKERS):
                has_negative = True
                break

        if not has_negative:
            findings.append(
                {
                    "severity": "p3",
                    "kind": "eval-no-negative-case",
                    "confidence": "verified",
                    "case_count": len(cases),
                    "has_purpose_or_adversarial_case": has_purpose_or_adversarial_case,
                    "message": (
                        f"`{cases_path.name}` enthält {len(cases)} Testfälle, aber keinen "
                        "Negative-Trigger-/Out-of-Scope-Fall (`should_trigger: false`, "
                        "`expected_modules: []` oder ID mit `negative`/`out-of-scope`/`no-trigger`)."
                    ),
                }
            )

    for case in cases:
        case_id = str(case.get("id", "<unbekannt>"))

        # v1.5 optional rubric fields validation
        if "must_not_claim" in case:
            mnc = case.get("must_not_claim")
            if not isinstance(mnc, list) or not all(isinstance(x, str) and x.strip() for x in mnc):
                findings.append(
                    {
                        "severity": "p3",
                        "kind": "eval-invalid-rubric",
                        "confidence": "verified",
                        "case_id": case_id,
                        "field": "must_not_claim",
                        "has_purpose_or_adversarial_case": has_purpose_or_adversarial_case,
                        "message": (
                            f"Eval-Fall `{case_id}` hat ein ungültiges `must_not_claim`-Feld "
                            "(erwartet: Liste aus nicht-leeren Strings)."
                        ),
                    }
                )

        if "verification_rubric" in case:
            vr = case.get("verification_rubric")
            valid_list = isinstance(vr, list) and len(vr) > 0 and all(isinstance(x, str) and x.strip() for x in vr)
            valid_dict = isinstance(vr, dict) and len(vr) > 0
            if not (valid_list or valid_dict):
                findings.append(
                    {
                        "severity": "p3",
                        "kind": "eval-invalid-rubric",
                        "confidence": "verified",
                        "case_id": case_id,
                        "field": "verification_rubric",
                        "has_purpose_or_adversarial_case": has_purpose_or_adversarial_case,
                        "message": (
                            f"Eval-Fall `{case_id}` hat ein ungültiges `verification_rubric`-Feld "
                            "(erwartet: nicht-leere Liste aus nicht-leeren Strings oder nicht-leeres Objekt)."
                        ),
                    }
                )

        if "expected_findings" in case:
            ef = case.get("expected_findings")
            if not isinstance(ef, list) or not all(isinstance(x, (str, dict)) for x in ef):
                findings.append(
                    {
                        "severity": "p3",
                        "kind": "eval-invalid-rubric",
                        "confidence": "verified",
                        "case_id": case_id,
                        "field": "expected_findings",
                        "has_purpose_or_adversarial_case": has_purpose_or_adversarial_case,
                        "message": (
                            f"Eval-Fall `{case_id}` hat ein ungültiges `expected_findings`-Feld "
                            "(erwartet: Liste aus Regel-IDs/Strings oder Objekten)."
                        ),
                    }
                )

        raw_mc = case.get("must_contain")
        prompt = case.get("prompt")
        if not isinstance(raw_mc, list) or not isinstance(prompt, str) or not prompt.strip():
            continue

        all_terms = [t.strip() for t in raw_mc if isinstance(t, str) and t.strip()]
        if not all_terms:
            continue

        prompt_low = prompt.lower()
        non_generic_terms = [
            t
            for t in all_terms
            if len(t) >= 6
            and not t.lower().endswith((".md", ".py", ".json"))
            and not t.startswith("--")
        ]
        leaked_non_generic = [t for t in non_generic_terms if t.lower() in prompt_low]
        leaked_all = [t for t in all_terms if t.lower() in prompt_low]
        ratio = len(leaked_all) / len(all_terms)

        if len(leaked_non_generic) >= 2 and ratio >= 0.6:
            findings.append(
                {
                    "severity": "p3",
                    "kind": "eval-prompt-leakage",
                    "confidence": "heuristic",
                    "case_id": case_id,
                    "leaked_terms": leaked_non_generic,
                    "leak_ratio": round(ratio, 3),
                    "has_purpose_or_adversarial_case": has_purpose_or_adversarial_case,
                    "message": (
                        f"Eval-Fall `{case_id}` zeigt mögliches Prompt-Leakage: "
                        f"{len(leaked_all)}/{len(all_terms)} ({ratio:.0%}) der `must_contain`-Begriffe "
                        f"(inkl. {leaked_non_generic}) stehen bereits wörtlich im Prompt."
                    ),
                }
            )

    return findings


_POSITIVE_TRIGGER_RE = re.compile(
    r"\b(use when|use whenever|use after|use for|use this skill|use to|trigger|verwenden wenn|nutzen wenn|anwenden wenn)\b",
    re.I,
)
_NEGATIVE_BOUNDARY_RE = re.compile(
    r"(don't use|do not use|not for|not intended for|avoid for|unrelated to|nicht verwenden|nicht für|nicht geeignet für|außerhalb von)",
    re.I,
)
_DESC_BUNDLED_SCRIPT_RE = re.compile(
    r"(\b[a-zA-Z0-9_-]+\.(?:py|sh)\b|bundled scripts?|mitgelieferte[ns]?\s+skript)",
    re.I,
)
_DESC_REF_CLAIM_RE = re.compile(
    r"(\breferences/|\bassets/|\bvorlagen?\b|\bchecklisten?\b|\btemplates?\b|\bkatalog\b)",
    re.I,
)
_DESC_EVAL_CLAIM_RE = re.compile(
    r"(\bevals/|\btest-suite\b|\bbenchmark(?:s|-suite)?\b)",
    re.I,
)
_NEG_TOPIC_EXTRACT_RE = re.compile(
    r"(?:don't use for|do not use for|not for|not intended for|avoid for|nicht verwenden für|nicht für|nicht geeignet für)\s+([^\n.;]+)",
    re.I,
)
_NEG_TOPIC_STOPWORDS = frozenset(
    {
        "general",
        "unrelated",
        "other",
        "allgemeine",
        "allgemeinen",
        "sonstige",
        "sonstigen",
        "skills",
        "skill",
        "prompts",
        "prompt",
        "code",
        "reviews",
        "review",
        "pure",
        "reine",
        "reinen",
        "oder",
        "and",
        "or",
        "with",
        "without",
        "ohne",
        "tasks",
        "aufgaben",
        "projects",
        "projekte",
        "files",
        "dateien",
        "folders",
        "ordner",
        "management",
        "editing",
        "contents",
        "application",
        "applications",
        "software",
        "engineering",
    }
)
_HEADING_NEGATION_RE = re.compile(
    r"(?:\bnicht\b|don't|do not|\babgrenzung\b|\banti-pattern|\bout of scope\b|\bgrenzen\b|\bwhen not\b|\bwann nicht\b|\bausschluss\b|\bexclud|\bscope\b|\btrigger)",
    re.I,
)
_DOMAIN_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fach-wissens-skill", re.compile(r"\b(synthese|chemie|reaktion|spektroskopie|medizin|recht|physik|mathematik|wissensdatenbank|handbuch|norm)\b", re.I)),
    ("workflow-prompt-skill", re.compile(r"\b(audit|review|verbesserungsanalyse|workflow|prompt|prompts|skill|skills|subagent|orchestrat|bericht|checkliste)\b", re.I)),
    ("coding-devops-skill", re.compile(r"\b(ci/cd|github actions|docker|kubernetes|repo|monorepo|lint|refactor|typescript|python|git|build|test|deployment|api)\b", re.I)),
)


def check_purpose_alignment(
    fm: dict[str, object],
    skill_text: str,
    all_files: set[str],
    md_texts: dict[str, str] | None = None,
) -> dict[str, object]:
    """Erfasst Zweck, Scope & Ziel-Domäne aus SKILL.md und prüft Claim-vs.-Reality sowie Trigger-Widersprüche."""
    _ = md_texts  # Optional für Abwärtskompatibilität & zukünftige Cross-Doc-Prüfungen
    name = str(fm.get("name", "") or "").strip()
    desc = str(fm.get("description", "") or "").strip()
    has_pos = bool(_POSITIVE_TRIGGER_RE.search(desc))
    neg_match = _NEGATIVE_BOUNDARY_RE.search(desc)
    has_neg = bool(neg_match)
    neg_excerpt = ""
    positive_desc = desc
    if neg_match:
        neg_excerpt = desc[neg_match.start() : min(len(desc), neg_match.start() + 140)].strip()
        positive_desc = desc[: neg_match.start()]

    header_text = f"{name}\n{positive_desc}"
    body_text = skill_text[:1500]
    inferred_domain = "allgemein"
    best_score = 0
    for dom_label, dom_re in _DOMAIN_HINTS:
        score = 2 * len(dom_re.findall(header_text)) + len(dom_re.findall(body_text))
        if score > best_score:
            best_score = score
            inferred_domain = dom_label

    normalized_files = {f.replace("\\", "/") for f in all_files}
    has_scripts = any(
        f.startswith("scripts/") and pathlib.Path(f).suffix.lower() in {".py", ".sh", ".bash", ".js", ".ts"}
        for f in normalized_files
    )
    has_refs_or_extra_md = any(
        f.startswith(("references/", "assets/")) or (f.lower().endswith(".md") and f != "SKILL.md")
        for f in normalized_files
    )
    has_evals = any(f.startswith("evals/") for f in normalized_files)

    claimed_capabilities: list[str] = []
    verified_capabilities: list[str] = []
    unbacked_claims: list[str] = []
    contradictions: list[str] = []
    needs_user_clarification = False

    issues: list[dict[str, object]] = []
    if len(desc) >= 80 and has_pos and not has_neg:
        issues.append(
            {
                "file": "SKILL.md",
                "severity": "p3",
                "kind": "purpose-missing-negative-boundary",
                "confidence": "heuristic",
                "message": (
                    "`SKILL.md`-`description` enthält Positiv-Trigger, aber keine explizite Negativ-Abgrenzung "
                    "(z. B. `Don't use for ...` / `Nicht verwenden für ...`) — erhöht das Risiko für Fehl-Trigger "
                    "und unpassende Architektur-Annahmen."
                ),
            }
        )

    if _DESC_BUNDLED_SCRIPT_RE.search(desc):
        claimed_capabilities.append("bundled_scripts")
        if has_scripts:
            verified_capabilities.append("bundled_scripts")
        else:
            unbacked_claims.append("bundled_scripts")
            issues.append(
                {
                    "file": "SKILL.md",
                    "severity": "p3",
                    "kind": "purpose-script-mismatch",
                    "confidence": "verified",
                    "message": (
                        "`SKILL.md`-`description` kündigt ein konkretes/mitgeliefertes Skript an, "
                        "im Ordner `scripts/` existiert jedoch keine ausführbare Skriptdatei."
                    ),
                }
            )
    elif has_scripts:
        verified_capabilities.append("bundled_scripts")

    # a) Ghost file / folder claim (purpose-unbacked-capability-claim)
    ref_claim_m = _DESC_REF_CLAIM_RE.search(desc)
    eval_claim_m = _DESC_EVAL_CLAIM_RE.search(desc)
    missing_bundle_claims: list[str] = []

    if ref_claim_m:
        claimed_capabilities.append("references_or_templates")
        if has_refs_or_extra_md:
            verified_capabilities.append("references_or_templates")
        else:
            unbacked_claims.append(f"references_or_templates ({ref_claim_m.group(0)})")
            missing_bundle_claims.append(f"Referenzen/Vorlagen (`{ref_claim_m.group(0)}`)")
    elif has_refs_or_extra_md:
        verified_capabilities.append("references_or_templates")

    if eval_claim_m:
        claimed_capabilities.append("evals_suite")
        if has_evals:
            verified_capabilities.append("evals_suite")
        else:
            unbacked_claims.append(f"evals_suite ({eval_claim_m.group(0)})")
            missing_bundle_claims.append(f"Eval-/Benchmark-Suite (`{eval_claim_m.group(0)}`)")
    elif has_evals:
        verified_capabilities.append("evals_suite")

    if missing_bundle_claims:
        issues.append(
            {
                "file": "SKILL.md",
                "severity": "p3",
                "kind": "purpose-unbacked-capability-claim",
                "confidence": "verified",
                "unbacked_claims": list(unbacked_claims),
                "message": (
                    "`SKILL.md`-`description` verspricht mitgelieferte Ressourcen ("
                    + ", ".join(missing_bundle_claims)
                    + "), die im Skill-Bundle real nicht existieren (Claim-vs.-Reality-Divergenz)."
                ),
            }
        )

    # b) Trigger vs. Body Contradiction (purpose-trigger-contradiction)
    excluded_phrases: list[tuple[str, tuple[str, ...]]] = []
    for m in _NEG_TOPIC_EXTRACT_RE.finditer(desc):
        clause = m.group(1).strip()
        for segment in re.split(r"[,;/]|\b(?:or|oder|and|und|nor|sowie)\b", clause, flags=re.I):
            words = [
                w.lower()
                for w in re.findall(r"[A-Za-zÄÖÜäöüß0-9_-]{5,}", segment)
                if w.lower() not in _NEG_TOPIC_STOPWORDS
            ]
            if words:
                excluded_phrases.append((segment.strip(), tuple(words)))

    if excluded_phrases:
        prose_lines = _strip_frontmatter_and_fences_preserve_lines(skill_text)
        for line_no, line in enumerate(prose_lines, start=1):
            hm = re.match(r"^(#{2,3})\s+(.+)$", line.strip())
            if not hm:
                continue
            heading_text = hm.group(2).strip()
            if _HEADING_NEGATION_RE.search(heading_text):
                continue
            heading_words = {w.lower() for w in re.findall(r"[A-Za-zÄÖÜäöüß0-9_-]{5,}", heading_text)}
            if not heading_words:
                continue
            for raw_seg, topic_tokens in excluded_phrases:
                matched_tokens = [tok for tok in topic_tokens if tok in heading_words]
                if (len(topic_tokens) >= 2 and len(matched_tokens) >= 2) or (
                    len(topic_tokens) == 1 and len(matched_tokens) == 1
                ):
                    contradiction_desc = (
                        f"Negativ-Trigger schließt `{raw_seg}` aus, aber Überschrift `{hm.group(0)}` "
                        f"(Zeile {line_no}) lehrt genau diesen Workflow."
                    )
                    contradictions.append(contradiction_desc)
                    issues.append(
                        {
                            "file": "SKILL.md",
                            "line": line_no,
                            "severity": "p3",
                            "kind": "purpose-trigger-contradiction",
                            "confidence": "verified",
                            "excluded_topic": raw_seg,
                            "heading": hm.group(0),
                            "message": (
                                f"Widerspruch zwischen Negativ-Trigger und Skill-Inhalt: `description` schließt "
                                f"`{raw_seg}` explizit aus, aber `{hm.group(0)}` (Zeile {line_no}) definiert dafür "
                                "einen eigenen Positiv-Workflow."
                            ),
                        }
                    )
                    break

    # c) Ambiguous / Under-specified Purpose (purpose-ambiguous-clarify-needed)
    if len(desc) < 45 or (inferred_domain == "allgemein" and not has_pos):
        needs_user_clarification = True
        issues.append(
            {
                "file": "SKILL.md",
                "severity": "p3",
                "kind": "purpose-ambiguous-clarify-needed",
                "confidence": "heuristic",
                "message": (
                    "`SKILL.md`-`description` ist zu kurz oder mehrdeutig, um Zweck, Ziel-Domäne und "
                    "erwartete Architektur belastbar abzuleiten — vor strukturellen Umbau-Empfehlungen "
                    "gezielt Rückfrage an den Nutzer stellen."
                ),
            }
        )

    return {
        "name": name,
        "description": desc,
        "has_positive_trigger": has_pos,
        "has_negative_boundary": has_neg,
        "negative_boundary_excerpt": neg_excerpt,
        "inferred_domain": inferred_domain,
        "has_bundled_scripts": has_scripts,
        "claimed_capabilities": claimed_capabilities,
        "verified_capabilities": verified_capabilities,
        "unbacked_claims": unbacked_claims,
        "contradictions": contradictions,
        "needs_user_clarification": needs_user_clarification,
        "issues": issues,
    }


def run_self_test() -> int:
    """Führt umfassende Selbsttests für alle 6 öffentlichen Qualitätsprüfungen + Adversarial Corpus aus."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)

        # --- 1. find_orphan_files ---
        assert find_orphan_files(root, {"README.md", "scripts/a.py"}, {}) == []

        (root / "scripts").mkdir()
        (root / "references").mkdir()
        (root / "assets").mkdir()

        skill_md_text = (
            "---\nname: demo-skill\ndescription: Test\n---\n"
            "# Demo\n"
            "Siehe [Guide](references/guide.md) und `scripts/skill_audit.py` sowie `README.md`.\n"
        )
        readme_text = "# Readme\nDiagramm: ![Arch](assets/diagram.svg)\n"
        guide_text = "# Guide\nMehr Details in `sub_ref.md`.\n"
        audit_py_text = (
            "import audit_security\n"
            "from audit_quality import find_orphan_files\n"
            "from . import helper_mod\n"
        )

        (root / "SKILL.md").write_text(skill_md_text, encoding="utf-8")
        (root / "README.md").write_text(readme_text, encoding="utf-8")
        (root / "references/guide.md").write_text(guide_text, encoding="utf-8")
        (root / "references/sub_ref.md").write_text("# Sub\n", encoding="utf-8")
        (root / "references/orphan_doc.md").write_text("# Orphan\n", encoding="utf-8")
        (root / "scripts/__init__.py").write_text("", encoding="utf-8")
        (root / "scripts/.hidden.py").write_text("", encoding="utf-8")
        (root / "scripts/skill_audit.py").write_text(audit_py_text, encoding="utf-8")
        (root / "scripts/audit_security.py").write_text("x = 1\n", encoding="utf-8")
        (root / "scripts/audit_quality.py").write_text("y = 2\n", encoding="utf-8")
        (root / "scripts/helper_mod.py").write_text("z = 3\n", encoding="utf-8")
        (root / "scripts/unused_tool.py").write_text("w = 4\n", encoding="utf-8")
        (root / "assets/diagram.svg").write_text("<svg/>", encoding="utf-8")
        (root / "assets/.gitkeep").write_text("", encoding="utf-8")
        (root / "assets/stale_logo.png").write_bytes(b"png")

        all_files = {
            "SKILL.md",
            "README.md",
            "references/guide.md",
            "references/sub_ref.md",
            "references/orphan_doc.md",
            "scripts/__init__.py",
            "scripts/.hidden.py",
            "scripts/skill_audit.py",
            "scripts/audit_security.py",
            "scripts/audit_quality.py",
            "scripts/helper_mod.py",
            "scripts/unused_tool.py",
            "assets/diagram.svg",
            "assets/.gitkeep",
            "assets/stale_logo.png",
        }
        md_texts = {
            "SKILL.md": skill_md_text,
            "README.md": readme_text,
            "references/guide.md": guide_text,
            "references/sub_ref.md": "# Sub\n",
            "references/orphan_doc.md": "# Orphan\n",
        }
        orphans = find_orphan_files(root, all_files, md_texts)
        orphan_files = [o["file"] for o in orphans]
        assert orphan_files == [
            "assets/stale_logo.png",
            "references/orphan_doc.md",
            "scripts/unused_tool.py",
        ], f"Orphan-Regression: {orphans}"
        assert all(o["severity"] == "p2" and o["kind"] == "orphan-file" for o in orphans)
        assert [o["directory"] for o in orphans] == ["assets", "references", "scripts"]

        # --- 2. validate_agentskills_spec ---
        valid_fm: dict[str, object] = {
            "name": "cafe\u0301-skill",  # NFD -> NFKC = café-skill
            "description": "Valid",
            "license": "MIT",
            "allowed-tools": "Bash Read",
            "metadata": {"version": "1.0"},
            "compatibility": "Python 3.10+",
        }
        # Matching dir in NFC form
        spec_ok = validate_agentskills_spec(valid_fm, pathlib.Path("/skills/caf\u00e9-skill"))
        assert spec_ok == [], f"NFKC-Valid-Regression: {spec_ok}"

        # tmp* dir skips directory mismatch
        spec_tmp = validate_agentskills_spec(
            {"name": "my-skill", "description": "desc"},
            pathlib.Path("/tmp/tmpabc123"),
        )
        assert spec_tmp == [], f"tmp-dir-Regression: {spec_tmp}"

        # Directory mismatch on non-tmp dir
        spec_mismatch = validate_agentskills_spec(
            {"name": "my-skill", "description": "desc"},
            pathlib.Path("/skills/other-dir"),
        )
        assert [(f["severity"], f["kind"]) for f in spec_mismatch] == [
            ("p3", "spec-name-dir-mismatch")
        ], f"dir-mismatch-Regression: {spec_mismatch}"

        # Invalid name cases
        for bad_name in ("", "Upper-Case", "-leading", "trailing-", "double--dash", "has_under", "a" * 65, 123):
            res = validate_agentskills_spec({"name": bad_name}, pathlib.Path("/tmp/tmp0"))
            kinds = [(f["severity"], f["kind"]) for f in res]
            assert ("p2", "spec-invalid-name") in kinds, f"bad_name={bad_name!r} -> {res}"

        # Invalid compatibility + non-standard fields
        spec_bad = validate_agentskills_spec(
            {
                "name": "good-skill",
                "compatibility": "x" * 501,
                "file_names": ["SKILL.md"],
                "version": "1.0",
            },
            pathlib.Path("/skills/good-skill"),
        )
        bad_kinds = [(f["severity"], f["kind"]) for f in spec_bad]
        assert ("p2", "spec-invalid-compatibility") in bad_kinds, spec_bad
        assert bad_kinds.count(("p3", "spec-nonstandard-field")) == 2, spec_bad

        spec_bad_compat_type = validate_agentskills_spec(
            {"name": "good-skill", "compatibility": ["py310"]},
            pathlib.Path("/skills/good-skill"),
        )
        assert [(f["severity"], f["kind"]) for f in spec_bad_compat_type] == [
            ("p2", "spec-invalid-compatibility")
        ], spec_bad_compat_type

        # --- 3. analyze_contamination ---
        c_clean = analyze_contamination(
            "python-helper",
            "Hilft bei Python-Skripten und JSON-Dateien.",
            ["python", "bash", "yaml", "sql", "html", "ts"],
        )
        assert c_clean["application_families"] == ["javascript", "python"], c_clean
        assert c_clean["auxiliary_families"] == ["config", "markup", "query", "shell"], c_clean
        assert c_clean["multi_interface_context"] is False
        assert c_clean["flagged"] is False

        c_flagged = analyze_contamination(
            "generic-helper",
            "Covers general coding laws without multi-interface tools.",
            ["python", "typescript", "rust", "bash", "json"],
        )
        assert c_flagged["application_families"] == ["javascript", "python", "systems"], c_flagged
        assert c_flagged["multi_interface_context"] is False  # 'laws' must not match 'aws'
        assert c_flagged["flagged"] is True

        c_multi_name = analyze_contamination(
            "stripe_payments",
            "SDK examples in multiple languages.",
            ["python", "javascript", "ruby", "csharp", "swift", "java"],
        )
        assert len(c_multi_name["application_families"]) == 6, c_multi_name
        assert c_multi_name["multi_interface_context"] is True
        assert c_multi_name["flagged"] is False

        c_multi_text = analyze_contamination(
            "db-client",
            "Connect to PostgreSQL and Redis from any app.",
            ["py", "go", "rb"],
        )
        assert c_multi_text["application_families"] == ["python", "ruby", "systems"], c_multi_text
        assert c_multi_text["multi_interface_context"] is True
        assert c_multi_text["flagged"] is False

        # --- 4. check_skill_prose_and_workflow ---
        prose_bad = (
            "---\n"
            "# Installation comment in frontmatter should be ignored\n"
            "name: wf-skill\n"
            "---\n"
            "# Workflow Skill\n"
            "## Installation\n"
            "Run pip install.\n"
            "```markdown\n"
            "## License\n"
            "Inside code fence must be ignored.\n"
            "```\n"
            "### Changelog\n"
            "v1.0\n"
            "### Step 1: Collect\n"
            "Read files.\n"
            "### Step 2: Transform\n"
            "Convert format.\n"
            "### Step 3: Emit\n"
            "Save result.\n"
        )
        prose_findings = check_skill_prose_and_workflow(prose_bad)
        prose_kinds = [f["kind"] for f in prose_findings]
        assert prose_kinds.count("readme-tier-in-skill") == 2, prose_findings
        assert prose_kinds.count("workflow-missing-verification") == 1, prose_findings
        assert all(f["severity"] == "p3" for f in prose_findings)

        prose_good = (
            "# Good Workflow\n"
            "## Phase 1: Bestandsaufnahme\n"
            "Messung ausführen.\n"
            "## Phase 2: Analyse\n"
            "Befunde verifizieren und erst bei Freigabe fortfahren.\n"
            "## Phase 3: Umsetzung\n"
            "Änderungen vornehmen.\n"
        )
        assert check_skill_prose_and_workflow(prose_good) == []

        prose_short = "## Schritt 1: Start\nLos.\n## Schritt 2: Ende\nFertig.\n"
        assert check_skill_prose_and_workflow(prose_short) == []

        # --- 5. check_evals_quality ---
        assert check_evals_quality(root / "does_not_exist.json") == []
        bad_json = root / "bad.json"
        bad_json.write_text("{not valid json", encoding="utf-8")
        assert check_evals_quality(bad_json) == []

        # Missing negative case + prompt leakage
        evals_bad = root / "evals_bad.json"
        evals_bad.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "id": "case-1",
                            "prompt": "Analysiere die Bestandsaufnahme und erstelle eine Priorisierung.",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["Bestandsaufnahme", "Priorisierung", "Fazit"],
                        },
                        {
                            "id": "case-2",
                            "prompt": "Run scripts/skill_audit.py --fail-on p2 on SKILL.md and cases.json",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["skill_audit.py", "--fail-on", "SKILL.md", "cases.json"],
                        },
                        {
                            "id": "case-3",
                            "prompt": "Prüfe den Ordner.",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["P1", "Bericht"],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        eq_bad = check_evals_quality(evals_bad)
        eq_kinds = [f["kind"] for f in eq_bad]
        assert eq_kinds == ["eval-no-negative-case", "eval-prompt-leakage"], eq_bad
        assert eq_bad[0]["confidence"] == "verified", eq_bad
        assert eq_bad[1]["confidence"] == "heuristic", eq_bad
        assert eq_bad[1]["case_id"] == "case-1", eq_bad

        # Good evals with negative trigger + v1.5 rubric fields
        for neg_case in (
            {
                "id": "c-neg",
                "prompt": "Irrelevant",
                "should_trigger": False,
                "must_contain": [],
                "must_not_claim": ["Auto-Fix ausgeführt"],
                "verification_rubric": ["Zweck vor Architektur geprüft", "Widerspruch erkannt"],
            },
            {"id": "c-empty", "prompt": "Irrelevant", "expected_modules": [], "must_contain": []},
            {"id": "eval-out-of-scope-1", "prompt": "Irrelevant", "expected_modules": ["SKILL.md"]},
        ):
            evals_ok = root / "evals_ok.json"
            evals_ok.write_text(
                json.dumps(
                    {
                        "cases": [
                            {"id": "c1", "prompt": "Do A", "expected_modules": ["SKILL.md"], "must_contain": ["alpha-result"]},
                            {"id": "c2", "prompt": "Do B", "expected_modules": ["SKILL.md"], "must_contain": ["beta-result"]},
                            neg_case,
                        ]
                    }
                ),
                encoding="utf-8",
            )
            assert check_evals_quality(evals_ok) == [], f"neg_case={neg_case}"

        # Malformed v1.5 rubric fields
        evals_bad_rubric = root / "evals_bad_rubric.json"
        evals_bad_rubric.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "id": "c-rubric-bad",
                            "prompt": "Prüfe den Zweck und Widerspruch im Skill.",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["SV-P3-09"],
                            "must_not_claim": "not-a-list",
                            "verification_rubric": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        eq_rubric = check_evals_quality(evals_bad_rubric)
        assert [f["kind"] for f in eq_rubric] == ["eval-invalid-rubric", "eval-invalid-rubric"], eq_rubric
        assert all(f["confidence"] == "verified" and f["has_purpose_or_adversarial_case"] is True for f in eq_rubric)
        assert has_purpose_or_adversarial_eval_case(evals_bad_rubric) is True

        # --- 6. check_purpose_alignment ---
        p_ok = check_purpose_alignment(
            {
                "name": "skill-audit",
                "description": (
                    "Strukturierte Prüfung für KI-Skills mit Skript-Unterstützung. "
                    "Use when auditing a SKILL.md. Don't use for unrelated app code reviews."
                ),
            },
            "# Audit\nRun `scripts/check.py`.",
            {"SKILL.md", "scripts/check.py"},
        )
        assert p_ok["has_positive_trigger"] is True
        assert p_ok["has_negative_boundary"] is True
        assert p_ok["inferred_domain"] == "workflow-prompt-skill", p_ok
        assert p_ok["needs_user_clarification"] is False, p_ok
        assert p_ok["unbacked_claims"] == [], p_ok
        assert p_ok["contradictions"] == [], p_ok
        assert p_ok["issues"] == [], p_ok

        p_bad = check_purpose_alignment(
            {
                "name": "mega-helper",
                "description": (
                    "Ausführlicher automatischer Validator mit helper.py für alle denkbaren Aufgaben im Projekt. "
                    "Use when running checks on any repository or documentation folder."
                ),
            },
            "# Mega Helper\nNo scripts bundled.",
            {"SKILL.md"},
        )
        p_bad_kinds = {x["kind"] for x in p_bad["issues"]}
        assert "purpose-missing-negative-boundary" in p_bad_kinds, p_bad
        assert "purpose-script-mismatch" in p_bad_kinds, p_bad
        assert all("confidence" in x for x in p_bad["issues"]), p_bad

        # --- 7. Adversarial Skill Testing Corpus ---
        # 1) Ghost-Feature Skill: claims auto_fix.py and evals/ benchmark suite, but bundle has only SKILL.md
        adv_ghost = check_purpose_alignment(
            {
                "name": "ghost-feature-skill",
                "description": (
                    "Automated validator with bundled auto_fix.py CLI and evals/ benchmark suite. "
                    "Use when validating skills. Don't use for application code."
                ),
            },
            "# Ghost Feature Skill\nPure prose without any bundled scripts or evals.",
            {"SKILL.md"},
        )
        adv_ghost_kinds = {x["kind"] for x in adv_ghost["issues"]}
        assert "purpose-script-mismatch" in adv_ghost_kinds, adv_ghost
        assert "purpose-unbacked-capability-claim" in adv_ghost_kinds, adv_ghost
        assert adv_ghost["unbacked_claims"], adv_ghost

        # 2) Contradictory-Trigger Skill: description excludes Kubernetes cluster deployment, body teaches it
        adv_contra = check_purpose_alignment(
            {
                "name": "sql-migrator",
                "description": (
                    "Use for database SQL schema migrations. "
                    "Don't use for Kubernetes cluster deployment."
                ),
            },
            (
                "# SQL Migrator\n"
                "## Database Schema Migration\n"
                "Run SQL migrations.\n"
                "## Kubernetes Cluster Deployment Workflow\n"
                "Deploy Helm charts to the cluster.\n"
            ),
            {"SKILL.md"},
        )
        adv_contra_kinds = {x["kind"] for x in adv_contra["issues"]}
        assert "purpose-trigger-contradiction" in adv_contra_kinds, adv_contra
        assert len(adv_contra["contradictions"]) == 1, adv_contra

        # 3) Under-specified / Ambiguous Skill: tiny vague description -> needs_user_clarification
        adv_ambig = check_purpose_alignment(
            {
                "name": "misc-helper",
                "description": "Helper for stuff.",
            },
            "# Helper\nDoes various things.",
            {"SKILL.md"},
        )
        adv_ambig_kinds = {x["kind"] for x in adv_ambig["issues"]}
        assert adv_ambig["needs_user_clarification"] is True, adv_ambig
        assert "purpose-ambiguous-clarify-needed" in adv_ambig_kinds, adv_ambig

        # 4) Fake-Optimization / Regression Skill: multi-step workflow without verification + README-tier + contamination + prompt-leaking eval
        adv_fake_text = (
            "---\n"
            "name: fake-opt-skill\n"
            "description: Optimizes general repositories across stacks. Use when optimizing code. Don't use for hardware.\n"
            "---\n"
            "# Fake Optimization Skill\n"
            "## Installation\n"
            "Install dependencies.\n"
            "### Step 1: Parse\n"
            "Read input.\n"
            "### Step 2: Rewrite\n"
            "Modify everything.\n"
            "### Step 3: Save\n"
            "Write files to disk.\n"
        )
        adv_fake_prose = check_skill_prose_and_workflow(adv_fake_text)
        adv_fake_prose_kinds = {x["kind"] for x in adv_fake_prose}
        assert "readme-tier-in-skill" in adv_fake_prose_kinds, adv_fake_prose
        assert "workflow-missing-verification" in adv_fake_prose_kinds, adv_fake_prose

        adv_fake_contam = analyze_contamination(
            "fake-opt-skill",
            adv_fake_text,
            ["python", "typescript", "rust"],
        )
        assert adv_fake_contam["flagged"] is True, adv_fake_contam

        adv_fake_eval_path = root / "adv_fake_evals.json"
        adv_fake_eval_path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "id": "leak-1",
                            "prompt": "Erstelle eine Architektur-Transformation und Performance-Kalibrierung.",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["Architektur-Transformation", "Performance-Kalibrierung"],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        adv_fake_eval_issues = check_evals_quality(adv_fake_eval_path)
        assert any(x["kind"] == "eval-prompt-leakage" for x in adv_fake_eval_issues), adv_fake_eval_issues

    print("OK: audit_quality.py Selbsttest (alle 7 Module inkl. Zweck-Abgleich, Rubrik-Evals & Adversarial Corpus) bestanden.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Eigenständige Qualitätsprüfungen für KI-Skills (audit_quality.py)"
    )
    parser.add_argument("--self-test", action="store_true", help="Selbsttest ausführen")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
