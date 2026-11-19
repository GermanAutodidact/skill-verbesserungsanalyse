#!/usr/bin/env python3
"""Automatisiertes Audit-Skript für KI-Skills, Wissensdatenbanken und Doku-Repos (v1.6-DE).

Misst und prüft:
1. Zweck-, Scope- & Architektur-Abgleich (Frontmatter-Description, Positiv-/Negativ-Trigger, Ziel-Domäne, Skript-Konsistenz)
2. Datei-Inventar (Zeichen, ≈Tokens, Zeilen, max. Zeilenlänge, Überschriften, TOC, LaTeX-Dichte) + Bundle-Budget
3. Abschnitts-Breakdown großer Dateien (>10k Tokens oder --sections)
4. SKILL.md-Frontmatter & agentskills.io-Spec (NFKC-name, compatibility, description <= 1024, DE/EN-Trigger, YAML Flow-Multiline/Listen/Block-Scalars, file_names-Abgleich, version)
5. Markdown-Integrität: defekte relative Links (inkl. URL-Decoding, Klammern & Link-Titel), defekte #Anker, ungeschlossene Codeblöcke (auch vor Folgeböcken), Mermaid-Lint, Überlängen (>1500 Z.)
6. Tote lokale Datei-/Skript-Verweise in Backticks & transitive Orphan-File-Erkennung (BFS ab SKILL.md)
7. Format-Lint (fehlende Leerzeichen & Trailing Whitespace — Codeblöcke/Backticks/LaTeX maskiert!)
8. Portabilität, Sandbox-Anti-Patterns & Security (Unicode-Smuggling/Bidi-Overrides, AST-Skript-Security, Shell-Risiken & Hardcoded Secrets)
9. Cross-Language-Contamination, README-Tier-/Workflow-Qualität & Datei-Duplikate
10. Repo-/Skill-Hygiene (Modus A vs. Modus B) inkl. __pycache__/Junk-Prüfung & evals/cases.json (Schema + Negative-Trigger/Leakage-Lint)
11. 28 stabile Regel-IDs (SV-P1-01…SV-P3-10), SARIF 2.1.0 Export (--sarif) & CI-Exit-Codes (--fail-on p1|p2|p3)

Nutzung:
  python3 skill_audit.py <ziel-ordner>                  # Markdown-Report
  python3 skill_audit.py <ziel-ordner> --sections       # inkl. Abschnittsgrößen aller Dateien
  python3 skill_audit.py <ziel-ordner> --report-draft   # Vorbefüllter Entwurf nach BERICHT_VORLAGE.md
  python3 skill_audit.py <ziel-ordner> --fail-on p2     # CI-/Validator-Modus (Exit 1 ab P2-Befund)
  python3 skill_audit.py <ziel-ordner> --sarif          # SARIF 2.1.0 Ausgabe (GitHub Code Scanning)
  python3 skill_audit.py <ziel-ordner> --json           # JSON-Ausgabe inkl. Regel-IDs
  python3 skill_audit.py --rules                        # Alle 28 stabilen Regel-IDs anzeigen
  python3 skill_audit.py --self-test                    # Erweiterter Selbsttest (v1.3–v1.6)
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys
import tempfile
import urllib.parse

sys.dont_write_bytecode = True

_SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import audit_quality  # noqa: E402
import audit_sarif  # noqa: E402
import audit_security  # noqa: E402

# Dateien, deren Backtick-Verweise typischerweise externe Quelleninventare statt lokaler Tools sind
ARCHIVE_FILE_RE = re.compile(r"(^|/)00_INDEX|KONTROLLLISTE|CHANGELOG|NOTICE", re.I)
EXTERNAL_PATH_PREFIXES = ("raw_sources/", "http://", "https://", "file://", "~/", "/")
STANDARD_META_FILES = {"README.md", "LICENSE", "NOTICE.md", "CHANGELOG.md", "SKILL.md"}
COMMON_PROJECT_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    "tsconfig.json",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Cargo.toml",
    "go.mod",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Makefile",
    ".editorconfig",
    ".gitignore",
    ".eslintrc.json",
    "vite.config.ts",
    "next.config.js",
}
JUNK_DIR_NAMES = {"__pycache__"}
JUNK_FILE_NAMES = {".DS_Store", "Thumbs.db"}
JUNK_SUFFIXES = {".pyc", ".pyo"}

SUPPORTED_MERMAID_TYPES = {
    "flowchart",
    "graph",
    "sequenceDiagram",
    "stateDiagram",
    "stateDiagram-v2",
    "classDiagram",
    "erDiagram",
    "xychart-beta",
}
SHELL_LANGS = {"", "bash", "sh", "zsh", "shell", "console"}

EN_TRIGGER_RE = re.compile(
    r"\b(use when|use whenever|use after|use for|use this skill|use to|trigger|don't use)\b",
    re.I,
)
DE_CONTENT_RE = re.compile(
    r"\b(verwenden|nutzen|anwenden|prüfen|überprüfen|verbessern|optimieren|erstellen|für|mit|und|oder|wenn|bei)\b|[äöüß]",
    re.I,
)
HARDCODED_PATH_RE = re.compile(
    r"(?:~/(?:\.gemini|\.claude|\.codex)/|/home/antigravity/|/Users/[A-Za-z0-9_.-]+/|C:\\Users\\)"
)
PORTABLE_DOC_CONTEXT_RE = re.compile(
    r"(<skill-dir>|<ziel-ordner>|je nach Plattform|z\.\s*B\.|oder\s+`?~/|statt\s+|kein\s+fest|nicht\s+hardcod|wie\s+`?~/|z\.\s*B\.\s+`?/)",
    re.I,
)
SANDBOX_CMD_RE = re.compile(r"(?:^|[;&|]\s*|\$\s*)(sudo\s+|apt-get\s+install\b|apt\s+install\b)")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(((?:[^()\s]+|\([^()\s]*\))+)(?:\s+[\"'][^\"']*[\"'])?\)")

GET_SKILL_RESOURCES_BYTE_LIMIT = 46_080


def _strip_yaml_inline_comment(val: str) -> str:
    """Entfernt YAML-Inline-Kommentare (# ...) außerhalb von Anführungszeichen."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(val):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or val[idx - 1].isspace():
                return val[:idx].rstrip()
    return val.strip()


def _parse_yaml_inline_list(val: str) -> list[str]:
    """Parst einfache YAML-Inline-Listen wie [a.md, 'b.md', "c.md"]."""
    inner = val[1:-1].strip()
    if not inner:
        return []
    items: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    for ch in inner:
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif ch == "," and not in_single and not in_double:
            token = "".join(buf).strip().strip("'\"")
            if token:
                items.append(token)
            buf = []
        else:
            buf.append(ch)
    last = "".join(buf).strip().strip("'\"")
    if last:
        items.append(last)
    return items


def parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """Parst YAML-Frontmatter inkl. CRLF, Flow-Multiline-Scalars, Inline-/Block-Listen, Maps und >/| Block-Scalars."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.startswith("---\n"):
        return {}, normalized
    end_idx = normalized.find("\n---\n", 4)
    if end_idx == -1:
        if normalized.endswith("\n---"):
            end_idx = len(normalized) - 4
        else:
            return {}, normalized
    fm_block = normalized[4:end_idx]
    body = normalized[end_idx + 5 :] if end_idx + 5 <= len(normalized) else ""

    data: dict[str, object] = {}
    current_key: str | None = None
    last_scalar_key: str | None = None
    block_key: str | None = None
    block_mode: str = ""
    block_lines: list[str] = []

    def flush_block() -> None:
        nonlocal block_key, block_mode, block_lines
        if block_key is not None:
            if block_mode == ">":
                joined = " ".join(l.strip() for l in block_lines if l.strip())
            else:
                joined = "\n".join(block_lines).strip()
            data[block_key] = joined
            block_key = None
            block_mode = ""
            block_lines = []

    for line in fm_block.splitlines():
        if block_key is not None:
            if line.startswith((" ", "\t")) or not line.strip():
                block_lines.append(line.strip() if block_mode == ">" else line.lstrip())
                continue
            flush_block()

        if not line.strip() or line.lstrip().startswith("#"):
            continue

        # Eingerückte Fortsetzungszeile eines Flow-Multiline-Scalars (ohne > / |)
        if line.startswith((" ", "\t")) and current_key is None and last_scalar_key is not None:
            cont = _strip_yaml_inline_comment(line.strip()).strip("'\"")
            if cont:
                prev = str(data.get(last_scalar_key, ""))
                data[last_scalar_key] = f"{prev} {cont}".strip()
            continue

        list_m = re.match(r"^\s+-\s+(.*)$", line)
        if list_m and current_key is not None:
            cur = data.get(current_key)
            if not isinstance(cur, list):
                cur = []
                data[current_key] = cur
            item_val = _strip_yaml_inline_comment(list_m.group(1).strip()).strip("'\"")
            cur.append(item_val)
            continue

        map_m = re.match(r"^\s{2,}([A-Za-z0-9_-]+):\s*(.*)$", line)
        if map_m and current_key is not None:
            cur = data.get(current_key)
            if not isinstance(cur, dict):
                cur = {}
                data[current_key] = cur
            m_val = _strip_yaml_inline_comment(map_m.group(2).strip()).strip("'\"")
            cur[map_m.group(1).strip()] = m_val
            continue

        current_key = None
        last_scalar_key = None
        if ":" in line:
            key, raw_val = line.split(":", 1)
            key = key.strip()
            val = _strip_yaml_inline_comment(raw_val.strip())
            if val in {">", ">-", ">+", "|", "|-", "|+"}:
                block_key = key
                block_mode = val[0]
                block_lines = []
                continue
            if val.startswith("[") and val.endswith("]"):
                data[key] = _parse_yaml_inline_list(val)
                continue
            val_unquoted = val.strip("'\"")
            if val_unquoted == "":
                data[key] = {}
                current_key = key
            else:
                data[key] = val_unquoted
                last_scalar_key = key
    flush_block()
    return data, body


def strip_fenced_code_blocks(text: str) -> tuple[str, int]:
    """Ersetzt Zeilen in Fenced Code Blocks durch Leerzeilen (CommonMark §4.5) und zählt ungeschlossene Fences."""
    out: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    unclosed_count = 0
    for line in text.splitlines():
        m = re.match(r"^\s*(`{3,}|~{3,})", line)
        if m:
            marker = m.group(1)
            rest = line[m.end() :]
            is_inline_backtick = marker[0] == "`" and "`" in rest
            if not in_fence:
                # CommonMark §4.5: Backtick-Fences duerfen kein '`' im Info-String enthalten
                if is_inline_backtick:
                    out.append(line)
                    continue
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                out.append("")
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                if line.strip() == marker:
                    in_fence = False
                    out.append("")
                    continue
                # F3: Neuer Fence mit Info-String (z. B. ```python) während vorheriger Fence offen ist
                if rest.strip() != "" and not is_inline_backtick:
                    unclosed_count += 1
                    fence_len = len(marker)
                    out.append("")
                    continue
        out.append("" if in_fence else line)
    if in_fence:
        unclosed_count += 1
    return "\n".join(out), unclosed_count


def iter_fenced_blocks(text: str) -> list[tuple[str, int, list[tuple[int, str]]]]:
    """Extrahiert Fenced Code Blocks als (lang, start_line_1based, [(line_no, line_text), ...])."""
    blocks: list[tuple[str, int, list[tuple[int, str]]]] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    cur_lang = ""
    cur_start = 0
    cur_lines: list[tuple[int, str]] = []

    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(`{3,}|~{3,})", line)
        if m:
            marker = m.group(1)
            rest = line[m.end() :]
            is_inline_backtick = marker[0] == "`" and "`" in rest
            if not in_fence:
                if is_inline_backtick:
                    continue
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                cur_lang = rest.strip().split()[0].lower() if rest.strip() else ""
                cur_start = lineno
                cur_lines = []
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                if line.strip() == marker:
                    blocks.append((cur_lang, cur_start, cur_lines))
                    in_fence = False
                    cur_lines = []
                    continue
                if rest.strip() != "" and not is_inline_backtick:
                    blocks.append((cur_lang, cur_start, cur_lines))
                    fence_len = len(marker)
                    cur_lang = rest.strip().split()[0].lower()
                    cur_start = lineno
                    cur_lines = []
                    continue
        if in_fence:
            cur_lines.append((lineno, line))
    if in_fence:
        blocks.append((cur_lang, cur_start, cur_lines))
    return blocks


def lint_mermaid_blocks(rel: str, blocks: list[tuple[str, int, list[tuple[int, str]]]]) -> list[dict[str, object]]:
    """Prüft Mermaid-Diagrammblöcke auf unterstützte Typen und unquotierte Klammern in Knotenlabels."""
    issues: list[dict[str, object]] = []
    for lang, start_ln, blines in blocks:
        if lang != "mermaid":
            continue
        diagram_type_checked = False
        for lineno, mline in blines:
            stripped = mline.strip()
            if not stripped or stripped.startswith("%%"):
                continue
            if not diagram_type_checked:
                diagram_type_checked = True
                first_tok = stripped.split()[0]
                if first_tok not in SUPPORTED_MERMAID_TYPES:
                    issues.append(
                        {
                            "file": rel,
                            "line": lineno,
                            "kind": "unsupported-mermaid-type",
                            "snippet": f"Diagrammtyp '{first_tok}' nicht unterstützt",
                        }
                    )
                continue
            # Unquotierte Klammern in Knotenlabel: id[Label (Extra)] statt id["Label (Extra)"]
            unquoted_m = re.search(r'(?:^|[\s>|-])([A-Za-z0-9_-]+)\[(?![\"(\[/\\])([^\]"]*[()][^\]"]*)\]', mline)
            if unquoted_m:
                issues.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "kind": "mermaid-unquoted-label",
                        "snippet": f"{unquoted_m.group(1)}[{unquoted_m.group(2)}] -> bitte in Anführungszeichen setzen",
                    }
                )
    return issues


def scan_portability_and_sandbox(
    rel: str,
    stripped_lines: list[str],
    blocks: list[tuple[str, int, list[tuple[int, str]]]],
) -> list[dict[str, object]]:
    """Erkennt hardcoded Plattform-Pfade sowie Sandbox-unverträgliche Befehle (sudo/apt-get in Shell-Blöcken)."""
    issues: list[dict[str, object]] = []
    # 1. Hardcoded Pfade in Prosa (außerhalb portabler Erklärungen/Beispiele)
    for i, sline in enumerate(stripped_lines, 1):
        if HARDCODED_PATH_RE.search(sline) and not PORTABLE_DOC_CONTEXT_RE.search(sline):
            issues.append(
                {
                    "file": rel,
                    "line": i,
                    "kind": "hardcoded-platform-path",
                    "snippet": sline.strip()[:90],
                }
            )
    # 2. Shell-Codeblöcke: Sandbox-Anti-Patterns (sudo, apt-get install) und hardcoded Pfade
    for lang, _, blines in blocks:
        if lang not in SHELL_LANGS:
            continue
        for lineno, bline in blines:
            bstripped = bline.strip()
            if not bstripped or bstripped.startswith("#"):
                continue
            if SANDBOX_CMD_RE.search(bstripped):
                issues.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "kind": "sandbox-anti-pattern",
                        "snippet": bstripped[:90],
                    }
                )
            if HARDCODED_PATH_RE.search(bstripped) and not PORTABLE_DOC_CONTEXT_RE.search(bstripped):
                issues.append(
                    {
                        "file": rel,
                        "line": lineno,
                        "kind": "hardcoded-platform-path",
                        "snippet": bstripped[:90],
                    }
                )
    return issues


def mask_inline_code_and_math(line: str) -> str:
    """Maskiert Inline-Code (`...`) und Inline-LaTeX ($...$) für fehlerfreies Prosa-Linting."""
    masked = re.sub(r"`[^`]*`", lambda m: " " * len(m.group(0)), line)
    masked = re.sub(r"\$\$[^$]*\$\$", lambda m: " " * len(m.group(0)), masked)
    masked = re.sub(r"(?<!\\)\$[^$\n]+?(?<!\\)\$", lambda m: " " * len(m.group(0)), masked)
    return masked


def _clean_heading_text(heading: str) -> str:
    cleaned = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", heading)
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    cleaned = re.sub(r"`([^`]*)`", r"\1", cleaned)
    cleaned = re.sub(r"\$[^$]*\$", "", cleaned)
    return cleaned.strip().lower()


def github_slug(heading: str) -> str:
    """Erzeugt den exakten GitHub-Anker-Slug (github-slugger: jedes Leerzeichen wird zu '-')."""
    cleaned = _clean_heading_text(heading)
    cleaned = re.sub(r"[^\w\s-]", "", cleaned, flags=re.U)
    return re.sub(r" ", "-", cleaned).strip("-")


def collapsed_slug(heading: str) -> str:
    """Alternative Slug-Form mit kollabierten Mehrfach-Leerzeichen (z. B. für einfache Markdown-Parser)."""
    cleaned = _clean_heading_text(heading)
    cleaned = re.sub(r"[^\w\s-]", "", cleaned, flags=re.U)
    return re.sub(r"\s+", "-", cleaned).strip("-")


def collect_anchors(text: str) -> set[str]:
    """Sammelt explizite <a id="..."> Anker sowie exakte und kollabierte GitHub-Überschrifts-Slugs."""
    stripped, _ = strip_fenced_code_blocks(text)
    anchors: set[str] = set()
    for m in re.finditer(r'<a\s+(?:id|name)=["\']([^"\']+)["\']', stripped):
        anchors.add(m.group(1))
    slug_counts: collections.Counter[str] = collections.Counter()
    for m in re.finditer(r"^#{1,6}\s+(.*)$", stripped, re.M):
        raw_h = m.group(1)
        primary = github_slug(raw_h)
        alt = collapsed_slug(raw_h)
        if not primary:
            continue
        idx = slug_counts[primary]
        anchors.add(primary if idx == 0 else f"{primary}-{idx}")
        if alt and alt != primary:
            anchors.add(alt if idx == 0 else f"{alt}-{idx}")
        slug_counts[primary] += 1
    return anchors


def has_toc(text: str) -> bool:
    """Erkennt ein echtes Inhaltsverzeichnis (ohne Fehlalarm bei Beispieltext in Code/Backticks)."""
    stripped, _ = strip_fenced_code_blocks(text)
    if re.search(r"^\s*<!--\s*TOC_START\s*-->\s*$", stripped, re.M):
        return True
    if re.search(
        r"^#{1,3}\s+.*(Inhaltsverzeichnis|Table of Contents|Gesamt-Inhaltsverzeichnis)",
        stripped,
        re.I | re.M,
    ):
        return True
    clean_lines = [mask_inline_code_and_math(l) for l in stripped.splitlines()]
    anchor_links = re.findall(r"\]\(#[A-Za-z0-9_-]+\)", "\n".join(clean_lines))
    return len(anchor_links) >= 3


def compute_sections(text: str) -> list[dict[str, object]]:
    """Berechnet Zeilenbereich, Zeichen und ≈Tokens für alle ##/###-Abschnitte einer Datei."""
    lines = text.splitlines(True)
    stripped_lines = strip_fenced_code_blocks(text)[0].splitlines()
    starts = [i for i, l in enumerate(stripped_lines) if re.match(r"^#{2,3}\s+", l)]
    sections: list[dict[str, object]] = []
    for idx, s in enumerate(starts):
        e = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        chunk = "".join(lines[s:e])
        sections.append(
            {
                "heading": lines[s].strip(),
                "start_line": s + 1,
                "end_line": e,
                "lines": e - s,
                "chars": len(chunk),
                "approx_tokens": round(len(chunk) / 3.5),
            }
        )
    return sections


def detect_safety_clause(skill_text: str) -> tuple[bool, str]:
    """Heuristik für eine echte Sicherheits-/Ethik-Schranke (nicht bloße Checklisten-Erwähnung)."""
    stripped, _ = strip_fenced_code_blocks(skill_text)
    if re.search(
        r"^#{1,4}\s+.*(Ethik|Sicherheits-?\s*Schranke|Dual-Use|Safety|Guardrail|Verbot)",
        stripped,
        re.I | re.M,
    ):
        return True, "Eigene Überschrift für Sicherheit/Ethik erkannt"
    for line in stripped.splitlines():
        if re.search(r"(Striktes Verbot|darf nicht|keine Anleitung|never provide|must refuse)", line, re.I) and re.search(
            r"(Betäubungsmittel|Sprengstoff|Kampfstoff|CBRN|Waffe|Malware|Exploit|illegal|Dual-Use)",
            line,
            re.I,
        ):
            return True, "Explizite Verbots-/Ablehnungsregel erkannt"
    return False, "Keine explizite Sicherheits-/Ethik-Schranke erkannt (Heuristik)"


def validate_evals(target: pathlib.Path, all_files: set[str], all_basenames: set[str]) -> list[str]:
    """Prüft evals/cases.json auf gültiges JSON, eindeutige IDs, Pflichtfelder, must_contain-Listen und expected_modules."""
    cases_path = target / "evals" / "cases.json"
    if not cases_path.is_file():
        return []
    issues: list[str] = []
    try:
        raw = json.loads(cases_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"evals/cases.json: Ungültiges JSON ({exc})"]

    cases = raw.get("cases") if isinstance(raw, dict) else raw
    if not isinstance(cases, list) or not cases:
        return ["evals/cases.json: Keine gültige nicht-leere 'cases'-Liste gefunden"]

    seen_ids: set[str] = set()
    for idx, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            issues.append(f"evals/cases.json: Fall #{idx} ist kein JSON-Objekt")
            continue
        raw_id = case.get("id")
        cid = str(raw_id or f"#{idx}")
        if raw_id:
            if str(raw_id) in seen_ids:
                issues.append(f"evals/cases.json ({cid}): Doppelte Fall-ID '{raw_id}'")
            seen_ids.add(str(raw_id))
        if not case.get("prompt"):
            issues.append(f"evals/cases.json ({cid}): Pflichtfeld 'prompt' fehlt oder ist leer")
        for list_field in ("must_contain", "must_not_contain"):
            if list_field in case:
                val = case[list_field]
                if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                    issues.append(f"evals/cases.json ({cid}): '{list_field}' muss eine Liste aus Strings sein")
        if "must_contain" not in case:
            issues.append(f"evals/cases.json ({cid}): Pflichtfeld 'must_contain' fehlt")
        mods = case.get("expected_modules") or []
        if isinstance(mods, list):
            for mod in mods:
                mod_s = str(mod)
                if "/" in mod_s:
                    exists = mod_s in all_files or any(f.endswith("/" + mod_s) for f in all_files)
                elif "." in mod_s:
                    exists = mod_s in all_files or mod_s in all_basenames
                else:
                    exists = mod_s in all_basenames or any(
                        b.startswith((mod_s + "_", mod_s + "-", mod_s + ".")) for b in all_basenames
                    )
                if not exists:
                    issues.append(f"evals/cases.json ({cid}): expected_module '{mod_s}' nicht gefunden")
    return issues


def audit_directory(target: pathlib.Path, include_all_sections: bool = False) -> dict[str, object]:
    target = target.resolve()
    is_git_repo = (target / ".git").exists()
    md_files = sorted(
        p for p in target.rglob("*.md") if ".git" not in p.parts and "node_modules" not in p.parts
    )

    junk_files: list[str] = []
    all_files: set[str] = set()
    bundle_total_bytes = 0
    non_md_files = 0
    non_md_bytes = 0

    for p in target.rglob("*"):
        if ".git" in p.parts or "node_modules" in p.parts:
            continue
        rel = p.relative_to(target).as_posix()
        if any(part in JUNK_DIR_NAMES for part in p.parts) or p.name in JUNK_FILE_NAMES or p.suffix in JUNK_SUFFIXES:
            if p.is_file():
                junk_files.append(rel)
            continue
        if p.is_file():
            all_files.add(rel)
            size = p.stat().st_size
            bundle_total_bytes += size
            if p.suffix.lower() != ".md":
                non_md_files += 1
                non_md_bytes += size

    junk_files.sort()
    all_basenames = {pathlib.Path(f).name for f in all_files}

    # Pre-read markdown files & anchor indices for cross-file link checks
    md_texts: dict[str, str] = {}
    md_anchors: dict[str, set[str]] = {}
    for p in md_files:
        rel = p.relative_to(target).as_posix()
        txt = p.read_text(encoding="utf-8", errors="replace")
        md_texts[rel] = txt
        md_anchors[rel] = collect_anchors(txt)

    inventory: list[dict[str, object]] = []
    section_breakdowns: dict[str, list[dict[str, object]]] = {}
    total_chars = 0
    total_tokens = 0
    total_latex_text = 0
    format_issues: list[dict[str, object]] = []
    trailing_ws_count = 0
    unclosed_code_blocks: list[str] = []
    broken_links: list[dict[str, object]] = []
    mermaid_issues: list[dict[str, object]] = []
    portability_and_sandbox_issues: list[dict[str, object]] = []
    long_lines: list[dict[str, object]] = []
    local_ref_tokens: dict[str, set[str]] = collections.defaultdict(set)
    external_ref_tokens: dict[str, set[str]] = collections.defaultdict(set)
    long_line_owners: dict[str, set[str]] = collections.defaultdict(set)

    for p in md_files:
        rel = p.relative_to(target).as_posix()
        text = md_texts[rel]
        lines = text.splitlines()
        stripped_text, unclosed = strip_fenced_code_blocks(text)
        stripped_lines = stripped_text.splitlines()
        fenced_blocks = iter_fenced_blocks(text)
        if unclosed:
            unclosed_code_blocks.append(rel)

        mermaid_issues.extend(lint_mermaid_blocks(rel, fenced_blocks))
        portability_and_sandbox_issues.extend(scan_portability_and_sandbox(rel, stripped_lines, fenced_blocks))

        chars = len(text)
        tokens = round(chars / 3.5)
        max_line = max((len(l) for l in lines), default=0)
        headings = len(re.findall(r"^#{1,3}\s+", stripped_text, re.M))
        latex_text = text.count("\\text{")
        toc = has_toc(text)

        total_chars += chars
        total_tokens += tokens
        total_latex_text += latex_text

        inventory.append(
            {
                "file": rel,
                "chars": chars,
                "approx_tokens": tokens,
                "lines": len(lines),
                "max_line_len": max_line,
                "headings": headings,
                "has_toc": toc,
                "latex_text_count": latex_text,
            }
        )

        if include_all_sections or tokens >= 10_000:
            secs = compute_sections(text)
            if secs:
                section_breakdowns[rel] = sorted(secs, key=lambda x: int(x["chars"]), reverse=True)[:10]

        is_archive_doc = bool(ARCHIVE_FILE_RE.search(rel))

        # Backtick file references (outside fenced code blocks)
        for m in re.finditer(r"`([A-Za-z0-9_./<>-]+\.(?:py|md|json|sh|yml|yaml|csv|obo))`", stripped_text):
            token = m.group(1)
            if "*" in token or "<" in token or ">" in token or token.startswith("."):
                continue
            if is_archive_doc or token.startswith(EXTERNAL_PATH_PREFIXES):
                external_ref_tokens[token].add(rel)
            else:
                local_ref_tokens[token].add(rel)

        # Markdown links [label](target) & #anchors (outside fenced code & inline code)
        for i, sline in enumerate(stripped_lines, 1):
            if len(sline) > 1500 and len(long_lines) < 20:
                long_lines.append({"file": rel, "line": i, "length": len(sline)})

            clean_line = mask_inline_code_and_math(sline)
            for lm in LINK_RE.finditer(clean_line):
                href = lm.group(1)
                if href.startswith(("http://", "https://", "mailto:", "file://", "conversation://")):
                    continue
                if "<" in href or ">" in href or "…" in href:
                    continue
                if href.startswith("#"):
                    anchor = urllib.parse.unquote(href[1:])
                    if anchor not in md_anchors[rel]:
                        broken_links.append({"file": rel, "line": i, "link": href, "reason": "Anker nicht gefunden"})
                else:
                    raw_path, _, raw_anchor = href.partition("#")
                    raw_path_no_q = raw_path.split("?", 1)[0]
                    path_part = urllib.parse.unquote(raw_path_no_q)
                    anchor_part = urllib.parse.unquote(raw_anchor)
                    resolved = (p.parent / path_part).resolve()
                    try:
                        resolved_rel = resolved.relative_to(target).as_posix()
                    except ValueError:
                        resolved_rel = ""
                    if not resolved.exists():
                        broken_links.append({"file": rel, "line": i, "link": href, "reason": "Zieldatei fehlt"})
                    elif anchor_part and resolved_rel in md_anchors and anchor_part not in md_anchors[resolved_rel]:
                        broken_links.append(
                            {"file": rel, "line": i, "link": href, "reason": f"Anker '#{anchor_part}' fehlt in {resolved_rel}"}
                        )

            # Trailing whitespace check (outside fenced code blocks)
            if sline != sline.rstrip(" \t"):
                trailing_ws_count += 1
                if len(format_issues) < 60:
                    format_issues.append(
                        {"file": rel, "line": i, "kind": "trailing-whitespace", "snippet": repr(sline[-25:])}
                    )

            # Spacing lint on prose only (inline code & LaTeX masked)
            for pat, kind in (
                (r":\*\*[A-Za-zÄÖÜäöü]", "colon-bold-no-space (:**Wort)"),
                (r"\),[A-Za-zÄÖÜäöü]", "paren-comma-no-space (),Wort)"),
                (r"[a-zäöüß],[A-ZÄÖÜ][a-zäöüß]{2,}", "word-comma-Word-no-space"),
            ):
                for hm in re.finditer(pat, clean_line):
                    s = max(0, hm.start() - 18)
                    e = min(len(sline), hm.end() + 18)
                    format_issues.append(
                        {"file": rel, "line": i, "kind": kind, "snippet": sline[s:e]}
                    )

            if len(sline.strip()) >= 100 and not sline.strip().startswith("| :---"):
                long_line_owners[sline.strip()].add(rel)

    # Dead references classification (L3 + Zielprojekt-Manifeste in Skill-Ordnern/-Repos ausblenden)
    has_skill_md = (target / "SKILL.md").is_file()
    dead_local_refs: list[dict[str, object]] = []
    for token, sources in sorted(local_ref_tokens.items()):
        base = pathlib.Path(token).name
        if "/" in token:
            found = token in all_files or any(f.endswith("/" + token) for f in all_files)
        else:
            found = token in all_files or base in all_basenames
        if not found:
            if "/" not in token and (
                (not is_git_repo and base in STANDARD_META_FILES)
                or (has_skill_md and base in COMMON_PROJECT_FILES)
            ):
                external_ref_tokens[token].update(sources)
            else:
                dead_local_refs.append({"reference": token, "mentioned_in": sorted(sources)})

    dead_external_refs_count = sum(
        1
        for token in external_ref_tokens
        if token not in all_files and pathlib.Path(token).name not in all_basenames
    )

    # Duplicate content across files
    pair_dups: collections.Counter[tuple[str, str]] = collections.Counter()
    for _, owners in long_line_owners.items():
        if len(owners) > 1:
            sorted_o = sorted(owners)
            for idx, a in enumerate(sorted_o):
                for b in sorted_o[idx + 1 :]:
                    pair_dups[(a, b)] += 1
    duplicate_pairs = [
        {"file_a": a, "file_b": b, "shared_long_lines": cnt}
        for (a, b), cnt in pair_dups.most_common(10)
        if cnt >= 5
    ]

    # Budget warnings (TOC >15k, Split >40k, get_skill_resources 46-KB-Limit)
    budget_warnings: list[str] = []
    for item in inventory:
        tok = int(item["approx_tokens"])
        if tok >= 15_000 and not item["has_toc"]:
            budget_warnings.append(f"`{item['file']}` hat ~{tok:,} Tokens ohne Inhaltsverzeichnis (TOC empfohlen).")
        if tok >= 40_000:
            budget_warnings.append(
                f"`{item['file']}` hat ~{tok:,} Tokens — Split oder Hinweis 'nicht komplett laden' prüfen."
            )
    exceeds_bundle_limit = (not is_git_repo) and bundle_total_bytes > GET_SKILL_RESOURCES_BYTE_LIMIT
    if exceeds_bundle_limit:
        budget_warnings.append(
            f"Gesamt-Bundle ({bundle_total_bytes:,} Bytes) überschreitet das 46-KB-Limit von `get_skill_resources` "
            "— Skripte direkt per Shell ausführen statt gemeinsam in den Kontext zu laden."
        )

    # Frontmatter, file_names-Abgleich, agentskills.io-Spec, Purpose, Contamination, Workflow & Safety
    skill_md = target / "SKILL.md"
    frontmatter_report: dict[str, object] = {"exists": skill_md.is_file()}
    frontmatter_file_names_issues: list[str] = []
    spec_issues: list[dict[str, object]] = []
    prose_workflow_issues: list[dict[str, object]] = []
    purpose_report: dict[str, object] = {
        "name": "",
        "description": "",
        "has_positive_trigger": False,
        "has_negative_boundary": False,
        "negative_boundary_excerpt": "",
        "inferred_domain": "allgemein",
        "has_bundled_scripts": False,
        "claimed_capabilities": [],
        "verified_capabilities": [],
        "unbacked_claims": [],
        "contradictions": [],
        "needs_user_clarification": False,
        "issues": [],
    }
    purpose_issues: list[dict[str, object]] = []
    consistency_issues: list[dict[str, object]] = []
    contamination: dict[str, object] = {
        "application_families": [],
        "auxiliary_families": [],
        "multi_interface_context": False,
        "flagged": False,
        "matched_multi_interface_tools": [],
    }
    safety_present = False
    safety_note = "SKILL.md nicht vorhanden"
    fm: dict[str, object] = {}
    if skill_md.is_file():
        s_text = md_texts.get("SKILL.md", skill_md.read_text(encoding="utf-8", errors="replace"))
        fm, _ = parse_frontmatter(s_text)
        desc = str(fm.get("description", ""))
        meta = fm.get("metadata", {})
        version = meta.get("version") if isinstance(meta, dict) else fm.get("version")
        has_en_trigger = bool(EN_TRIGGER_RE.search(desc))
        has_de_content = bool(DE_CONTENT_RE.search(desc))
        fnames = fm.get("file_names")
        if isinstance(fnames, list):
            for fn in fnames:
                fn_s = str(fn)
                if "__pycache__" in fn_s or fn_s.endswith((".pyc", ".pyo")):
                    frontmatter_file_names_issues.append(f"Frontmatter `file_names` enthält Bytecode-Datei: `{fn_s}`")
                elif fn_s not in all_files:
                    frontmatter_file_names_issues.append(f"Frontmatter `file_names`-Eintrag fehlt im Ordner: `{fn_s}`")
        frontmatter_report.update(
            {
                "name": fm.get("name"),
                "description_len": len(desc),
                "description_within_1024": 0 < len(desc) <= 1024,
                "bilingual_en_trigger": has_en_trigger,
                "has_de_content": has_de_content,
                "bilingual_de_en": has_en_trigger and has_de_content,
                "version": version,
                "file_names_count": len(fnames) if isinstance(fnames, list) else 0,
            }
        )
        safety_present, safety_note = detect_safety_clause(s_text)
        spec_issues = audit_quality.validate_agentskills_spec(fm, target)
        purpose_report = audit_quality.check_purpose_alignment(fm, s_text, all_files, md_texts=md_texts)
        purpose_issues = list(purpose_report.get("issues", []))  # type: ignore[arg-type]
        skill_code_langs = [lang for lang, _, _ in iter_fenced_blocks(s_text) if lang]
        contamination = audit_quality.analyze_contamination(str(fm.get("name", "")), s_text, skill_code_langs)
        prose_workflow_issues = audit_quality.check_skill_prose_and_workflow(s_text)
        fm_for_consistency = dict(fm)
        if version and not fm_for_consistency.get("version"):
            fm_for_consistency["version"] = version
        consistency_issues = audit_sarif.check_version_and_rule_consistency(target, fm_for_consistency)

    # Evals schema, expected_modules & v1.4/v1.5 quality/leakage/rubric validation
    evals_issues = validate_evals(target, all_files, all_basenames)
    evals_quality_issues = audit_quality.check_evals_quality(target / "evals" / "cases.json")

    # v1.4/v1.5 Security (Unicode smuggling, Bidi, AST/Shell/JS/TS/PS1/Env/Toml security, coverage) & Orphan files
    sorted_all_files = sorted(all_files)
    sec_res = audit_security.scan_repository_security(target, sorted_all_files)
    unicode_smuggling_issues = list(sec_res.get("unicode_smuggling_issues", []))  # type: ignore[arg-type]
    script_security_issues = list(sec_res.get("script_security_issues", []))  # type: ignore[arg-type]
    security_coverage = dict(sec_res.get("security_coverage", {}))  # type: ignore[arg-type]
    orphan_files = audit_quality.find_orphan_files(target, all_files, md_texts)
    process_lifecycle_issues = audit_quality.scan_process_lifecycle(target, sorted_all_files)

    # Hygiene (differentiated for Mode A: skill dir vs Mode B: git repo)
    hygiene: dict[str, bool] = {
        "SKILL.md": skill_md.is_file(),
        "evals/": (target / "evals").is_dir() and any((target / "evals").iterdir()) and not evals_issues,
        "scripts/": (target / "scripts").is_dir() and any((target / "scripts").glob("*.py")),
        "no_bytecode_or_junk": len(junk_files) == 0,
    }
    if is_git_repo:
        hygiene.update(
            {
                "README.md": (target / "README.md").is_file(),
                "LICENSE": (target / "LICENSE").is_file() or (target / "LICENSE.md").is_file(),
                "NOTICE.md": (target / "NOTICE.md").is_file() or (target / "NOTICE").is_file(),
                "CHANGELOG.md": (target / "CHANGELOG.md").is_file(),
                "ci_workflow": (target / ".github/workflows").is_dir()
                and any((target / ".github/workflows").glob("*.y*ml")),
                "validator_script": any(target.glob("scripts/validate*.py"))
                or (target / "scripts/skill_audit.py").is_file(),
                ".gitignore": (target / ".gitignore").is_file(),
            }
        )

    report: dict[str, object] = {
        "target": str(target),
        "mode": "git-repo" if is_git_repo else "skill-folder",
        "tool_version": audit_sarif.TOOL_VERSION,
        "summary": {
            "markdown_files": len(md_files),
            "non_md_files": non_md_files,
            "non_md_bytes": non_md_bytes,
            "bundle_total_bytes": bundle_total_bytes,
            "exceeds_get_skill_resources_limit": exceeds_bundle_limit,
            "total_chars": total_chars,
            "total_approx_tokens": total_tokens,
            "total_latex_text_macros": total_latex_text,
            "dead_local_reference_count": len(dead_local_refs),
            "external_or_archive_reference_count": dead_external_refs_count,
            "orphan_file_count": len(orphan_files),
            "broken_link_count": len(broken_links),
            "unclosed_code_blocks": unclosed_code_blocks,
            "mermaid_issue_count": len(mermaid_issues),
            "portability_and_sandbox_issue_count": len(portability_and_sandbox_issues),
            "unicode_smuggling_issue_count": len(unicode_smuggling_issues),
            "script_security_issue_count": len(script_security_issues),
            "process_lifecycle_issue_count": len(process_lifecycle_issues),
            "security_scanned_files": int(security_coverage.get("scanned_count", 0)),
            "security_skipped_files": int(security_coverage.get("skipped_count", 0)),
            "spec_issue_count": len(spec_issues),
            "purpose_issue_count": len(purpose_issues),
            "consistency_issue_count": len(consistency_issues),
            "contamination_flagged": bool(contamination.get("flagged")),
            "prose_workflow_issue_count": len(prose_workflow_issues),
            "evals_quality_issue_count": len(evals_quality_issues),
            "long_line_count": len(long_lines),
            "format_issue_count": len(format_issues),
            "trailing_whitespace_lines": trailing_ws_count,
            "duplicate_file_pairs": len(duplicate_pairs),
            "evals_issue_count": len(evals_issues),
            "frontmatter_file_names_issue_count": len(frontmatter_file_names_issues),
            "junk_file_count": len(junk_files),
            "budget_warning_count": len(budget_warnings),
            "safety_clause_present": safety_present,
            "safety_clause_note": safety_note,
        },
        "frontmatter": frontmatter_report,
        "purpose": purpose_report,
        "purpose_issues": purpose_issues,
        "consistency_issues": consistency_issues,
        "security_coverage": security_coverage,
        "inventory": inventory,
        "section_breakdowns": section_breakdowns,
        "broken_links": broken_links[:50],
        "mermaid_issues": mermaid_issues[:30],
        "portability_and_sandbox_issues": portability_and_sandbox_issues[:30],
        "unicode_smuggling_issues": unicode_smuggling_issues[:50],
        "script_security_issues": script_security_issues[:50],
        "process_lifecycle_issues": process_lifecycle_issues[:50],
        "orphan_files": orphan_files[:50],
        "spec_issues": spec_issues,
        "contamination": contamination,
        "prose_workflow_issues": prose_workflow_issues,
        "evals_quality_issues": evals_quality_issues,
        "long_lines": long_lines,
        "dead_local_references": dead_local_refs,
        "format_issues": format_issues[:50],
        "duplicate_pairs": duplicate_pairs,
        "evals_issues": evals_issues,
        "frontmatter_file_names_issues": frontmatter_file_names_issues,
        "junk_files": junk_files[:30],
        "budget_warnings": budget_warnings,
        "hygiene": hygiene,
    }
    findings = audit_sarif.extract_findings(report)
    report["findings"] = findings
    report["summary"]["finding_count"] = len(findings)  # type: ignore[index]
    return report


def evaluate_fail_on(report: dict[str, object], threshold: str) -> list[str]:
    """Ermittelt CI-Fehlergründe für --fail-on (none|p1|p2|p3)."""
    if threshold == "none":
        return []
    s = report["summary"]
    fm = report["frontmatter"]
    reasons: list[str] = []

    # P1: Struktur-/Sicherheits-/Ausführungsblocker
    if s["unclosed_code_blocks"]:
        reasons.append(f"P1 [SV-P1-01]: Ungeschlossene Codeblöcke in {', '.join(s['unclosed_code_blocks'])}")
    if any("Ungültiges JSON" in str(ei) for ei in report["evals_issues"]):
        reasons.append("P1 [SV-P1-02]: Ungültiges JSON in evals/cases.json")
    sandbox_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "sandbox-anti-pattern"]
    if sandbox_hits:
        reasons.append(f"P1 [SV-P1-03]: {len(sandbox_hits)} Sandbox-Anti-Pattern(s) (sudo/apt-get) in Shell-Blöcken")
    uni_p1 = [x for x in report.get("unicode_smuggling_issues", []) if x.get("severity") == "p1"]
    if uni_p1:
        reasons.append(f"P1 [SV-P1-04]: {len(uni_p1)} Unicode-Tag-Smuggling-/Bidi-Override-Befund(e)")
    sec_p1 = [x for x in report.get("script_security_issues", []) if x.get("severity") == "p1"]
    if sec_p1:
        reasons.append(f"P1 [SV-P1-05/06]: {len(sec_p1)} kritische Skript-Security-/Secret-Befund(e)")
    if threshold == "p1":
        return reasons

    # P2: Defekte Links, tote Verweise, Orphan-Files, Format-/Mermaid-Lint, Evals-Schema, Spec, Junk, Zero-Width/Pickle/audit-ok
    if s["broken_link_count"]:
        reasons.append(f"P2 [SV-P2-01]: {s['broken_link_count']} defekte Links/Anker")
    if s["dead_local_reference_count"]:
        reasons.append(f"P2 [SV-P2-02]: {s['dead_local_reference_count']} tote lokale Verweise")
    if s.get("orphan_file_count"):
        reasons.append(f"P2 [SV-P2-03]: {s['orphan_file_count']} verwaiste Datei(en) (Orphan-Files)")
    if s["format_issue_count"]:
        reasons.append(f"P2 [SV-P2-04]: {s['format_issue_count']} Formatierungsfehler")
    if s["mermaid_issue_count"]:
        reasons.append(f"P2 [SV-P2-05]: {s['mermaid_issue_count']} Mermaid-Lint-Befunde")
    if s["evals_issue_count"]:
        reasons.append(f"P2 [SV-P2-06]: {s['evals_issue_count']} Eval-Schema-Fehler")
    if s["frontmatter_file_names_issue_count"]:
        reasons.append(f"P2 [SV-P2-07]: {s['frontmatter_file_names_issue_count']} fehlerhafte Frontmatter-file_names")
    if s["junk_file_count"]:
        reasons.append(f"P2 [SV-P2-08]: {s['junk_file_count']} Bytecode-/Junk-Dateien (__pycache__/.pyc/.DS_Store)")
    spec_p2 = [x for x in report.get("spec_issues", []) if x.get("severity") == "p2"]
    if spec_p2:
        reasons.append(f"P2 [SV-P2-09]: {len(spec_p2)} agentskills.io-Spec-Fehler")
    uni_p2 = [x for x in report.get("unicode_smuggling_issues", []) if x.get("severity") == "p2"]
    if uni_p2:
        reasons.append(f"P2 [SV-P2-10]: {len(uni_p2)} unsichtbare Zero-Width-/Steuerzeichen")
    sec_p2 = [x for x in report.get("script_security_issues", []) if x.get("severity") == "p2"]
    if sec_p2:
        reasons.append(f"P2 [SV-P2-11]: {len(sec_p2)} P2-Skript-Security-Befunde (Deserialisierung / unbegründeter audit-ok-Marker)")
    if s.get("process_lifecycle_issue_count"):
        reasons.append(f"P2 [SV-P2-12]: {s['process_lifecycle_issue_count']} Prozess-Lifecycle-/Orphan-Risiko-Befund(e)")
    if threshold == "p2":
        return reasons

    # P3: Frontmatter-Limits/Trigger, Hardcoded-Pfade, Budget-Warnungen, Spec-Advisories, Contamination, Workflow, Eval-Qualität, Purpose, Consistency
    if fm.get("exists"):
        if not fm.get("description_within_1024"):
            reasons.append("P3 [SV-P3-01]: SKILL.md description fehlt oder > 1024 Zeichen")
        if not fm.get("bilingual_en_trigger"):
            reasons.append("P3 [SV-P3-02]: Englischer Trigger in SKILL.md description fehlt")
    path_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "hardcoded-platform-path"]
    if path_hits:
        reasons.append(f"P3 [SV-P3-03]: {len(path_hits)} hardcoded Plattform-Pfade")
    if s["budget_warning_count"]:
        reasons.append(f"P3 [SV-P3-04]: {s['budget_warning_count']} Budget-/TOC-Warnungen")
    spec_p3 = [x for x in report.get("spec_issues", []) if x.get("severity") == "p3"]
    if spec_p3:
        reasons.append(f"P3 [SV-P3-05]: {len(spec_p3)} agentskills.io-Spec-Hinweis(e)")
    if s.get("contamination_flagged"):
        reasons.append("P3 [SV-P3-06]: Cross-Language-Contamination in SKILL.md erkannt")
    if s.get("prose_workflow_issue_count"):
        reasons.append(f"P3 [SV-P3-07]: {s['prose_workflow_issue_count']} README-Tier-/Workflow-Hinweis(e) in SKILL.md")
    if s.get("evals_quality_issue_count"):
        reasons.append(f"P3 [SV-P3-08]: {s['evals_quality_issue_count']} Eval-Qualitäts-/Leakage-Hinweis(e)")
    if s.get("purpose_issue_count"):
        reasons.append(f"P3 [SV-P3-09]: {s['purpose_issue_count']} Purpose-/Scope-Abgleich-Hinweis(e)")
    if s.get("consistency_issue_count"):
        reasons.append(f"P3 [SV-P3-10]: {s['consistency_issue_count']} Versions-/Regel-Konsistenz-Hinweis(e)")
    return reasons


def render_markdown(report: dict[str, object]) -> str:
    s = report["summary"]
    fm = report["frontmatter"]
    purp = report.get("purpose") or {}
    hyg = report["hygiene"]
    safety_suffix = "" if s["safety_clause_present"] else " *(nur bei sicherheitskritischen Domänen erforderlich)*"
    desc_preview = str(purp.get("description", "") or "").strip()
    if len(desc_preview) > 220:
        desc_preview = desc_preview[:217].rstrip() + "…"
    lines = [
        f"# Automatisierter Skill-Audit: `{pathlib.Path(str(report['target'])).name}` ({report['mode']})",
        "",
        "## 1. Zweck, Kennzahlen & Frontmatter",
        f"- **Erfasster Zweck & Ziel-Domäne:** `{purp.get('inferred_domain', 'allgemein')}` | "
        f"Positiv-Trigger: {purp.get('has_positive_trigger', False)} | "
        f"Negativ-Abgrenzung (`Don't use`): {purp.get('has_negative_boundary', False)}",
        f"- **Beschreibung (Auszug):** {desc_preview or '_(keine description in SKILL.md)_'}",
        f"- **Markdown-Dateien:** {s['markdown_files']} | **Gesamtgröße (MD):** {s['total_chars']:,} Zeichen (≈ {s['total_approx_tokens']:,} Tokens)",
        f"- **Nicht-MD-Ressourcen:** {s['non_md_files']} Dateien ({s['non_md_bytes']:,} Bytes) | **Bundle gesamt:** {s['bundle_total_bytes']:,} Bytes",
        f"- **LaTeX `\\text{{...}}`-Makros:** {s['total_latex_text_macros']:,}",
        f"- **SKILL.md Frontmatter:** `name={fm.get('name')}`, `version={fm.get('version')}`, "
        f"`description`={fm.get('description_len')} Zeichen (≤1024: {fm.get('description_within_1024')}, "
        f"EN-Trigger: {fm.get('bilingual_en_trigger')}, DE+EN: {fm.get('bilingual_de_en')})",
        f"- **Sicherheits-/Ethik-Schranke (Heuristik):** {s['safety_clause_present']} — _{s['safety_clause_note']}_{safety_suffix}",
        "",
        "## 2. Datei-Inventar (Größe ≈ Tokens & TOC)",
        "",
        "| Datei | Zeichen | ≈ Tokens | Zeilen | Max. Zeile | Überschriften | TOC |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | :---: |",
    ]
    for item in report["inventory"]:
        toc_mark = "✅" if item["has_toc"] else "❌"
        lines.append(
            f"| `{item['file']}` | {item['chars']:,} | ~{item['approx_tokens']:,} | "
            f"{item['lines']} | {item['max_line_len']} | {item['headings']} | {toc_mark} |"
        )

    if report["budget_warnings"]:
        lines.extend(["", "### Budget- & TOC-Hinweise"])
        for bw in report["budget_warnings"]:
            lines.append(f"- ⚠️ {bw}")

    if report["section_breakdowns"]:
        lines.extend(["", "## 2b. Abschnitts-Breakdown großer Dateien (Top-Verbraucher)", ""])
        for fname, secs in report["section_breakdowns"].items():
            lines.append(f"### `{fname}`")
            lines.append("| Abschnitt | Zeilen | Zeichen | ≈ Tokens |")
            lines.append("| :--- | :---: | ---: | ---: |")
            for sec in secs:
                h = str(sec["heading"]).replace("|", "\\|")[:85]
                lines.append(
                    f"| {h} | Z. {sec['start_line']}–{sec['end_line']} | {sec['chars']:,} | ~{sec['approx_tokens']:,} |"
                )
            lines.append("")

    lines.extend(["", "## 3. Markdown-Links, Anker, Codeblöcke & Mermaid", ""])
    if report["broken_links"]:
        for bl in report["broken_links"]:
            lines.append(f"- ❌ `{bl['file']}:{bl['line']}` → `{bl['link']}` ({bl['reason']})")
    else:
        lines.append("- ✅ Keine defekten relativen Markdown-Links oder `#Anker`.")
    if s["unclosed_code_blocks"]:
        lines.append(f"- ❌ Ungeschlossene Fenced Code Blocks (```` ``` ````): {', '.join(s['unclosed_code_blocks'])}")
    else:
        lines.append("- ✅ Alle Fenced Code Blocks sauber geschlossen.")
    if report["mermaid_issues"]:
        for mi in report["mermaid_issues"]:
            lines.append(f"- ❌ Mermaid `{mi['file']}:{mi['line']}` [{mi['kind']}]: {mi['snippet']}")
    else:
        lines.append("- ✅ Keine Mermaid-Syntax-Probleme gefunden.")

    lines.extend(["", "## 4. Tote lokale Datei-/Skript-Verweise & verwaiste Dateien (Orphans)", ""])
    if report["dead_local_references"]:
        for d in report["dead_local_references"]:
            lines.append(f"- ❌ Toter Verweis: `{d['reference']}` (erwähnt in: {', '.join(d['mentioned_in'])})")
    else:
        lines.append("- ✅ Keine toten lokalen Datei-Verweise gefunden.")
    if report.get("orphan_files"):
        for of in report["orphan_files"]:
            lines.append(f"- ❌ Verwaiste Datei (`SV-P2-03`): `{of['file']}` ({of['message']})")
    else:
        lines.append("- ✅ Keine verwaisten Dateien (Orphan-Files) in `scripts/`/`references/`/`assets/`.")
    if s["external_or_archive_reference_count"]:
        lines.append(
            f"- ℹ️ Zusätzlich {s['external_or_archive_reference_count']} externe/Zielprojekt-/Quell-Archiv-Pfade ausgeblendet."
        )

    cov = report.get("security_coverage") or {}
    lines.extend(
        [
            "",
            "## 5. Format-Lint, Portabilität, Sandbox & Security",
            "",
            f"- **Security-Scan-Coverage:** {cov.get('scanned_count', s.get('security_scanned_files', 0))} Dateien geprüft, "
            f"{cov.get('skipped_count', s.get('security_skipped_files', 0))} übersprungen.",
        ]
    )
    if report["format_issues"]:
        for fi in report["format_issues"]:
            lines.append(f"- `{fi['file']}:{fi['line']}` [{fi['kind']}]: `{fi['snippet']}`")
    else:
        lines.append("- ✅ Keine Formatierungsfehler (fehlende Leerzeichen / Trailing Whitespace) gefunden.")
    if report["portability_and_sandbox_issues"]:
        for ps in report["portability_and_sandbox_issues"]:
            lines.append(f"- ⚠️ `{ps['file']}:{ps['line']}` [{ps['kind']}]: `{ps['snippet']}`")
    else:
        lines.append("- ✅ Keine hardcoded Plattform-Pfade oder Sandbox-Anti-Patterns (`sudo`/`apt-get`) gefunden.")
    if report.get("unicode_smuggling_issues"):
        for ui in report["unicode_smuggling_issues"]:
            lines.append(
                f"- ❌ Unicode `{ui['file']}:{ui['line']}` [{ui['severity'].upper()} / {ui['kind']}]: "
                f"{ui['codepoint']} ({ui['name']}) — `{ui['snippet']}`"
            )
    else:
        lines.append("- ✅ Keine Unicode-Smuggling-, Bidi-Override- oder Zero-Width-Zeichen gefunden.")
    if report.get("script_security_issues"):
        for si in report["script_security_issues"]:
            conf_tag = "Verifiziert" if si.get("confidence", "verified") == "verified" else "Heuristik"
            lines.append(
                f"- ❌ Security `{si['file']}:{si['line']}` [{si['severity'].upper()} / {si['kind']} / {conf_tag}]: "
                f"{si['message']} (`{si['snippet']}`)"
            )
    else:
        lines.append("- ✅ Keine AST-Skript-Risiken, gefährlichen Shell-/JS-/PS1-Muster, unbegründeten `audit-ok`-Marker oder Hardcoded Secrets gefunden.")
    if report.get("process_lifecycle_issues"):
        for pli in report["process_lifecycle_issues"]:
            conf_tag = "Verifiziert" if pli.get("confidence", "verified") == "verified" else "Heuristik"
            lines.append(
                f"- ❌ Prozess-Lifecycle `{pli['file']}:{pli['line']}` [`SV-P2-12` / {pli['kind']} / {conf_tag}]: "
                f"{pli['message']} (`{pli['snippet']}`)"
            )
    else:
        lines.append("- ✅ Keine Prozess-Lifecycle- oder Orphan-Process-Risiken (`SV-P2-12`) gefunden.")
    if report["long_lines"]:
        for ll in report["long_lines"][:10]:
            lines.append(f"- ℹ️ Überlange Zeile (>1.500 Z.): `{ll['file']}:{ll['line']}` ({ll['length']:,} Zeichen)")

    lines.extend(["", "## 6. Spec, Qualität, Contamination & Duplikate", ""])
    if report.get("purpose_issues"):
        for pui in report["purpose_issues"]:
            conf_tag = "Verifiziert" if pui.get("confidence", "verified") == "verified" else "Heuristik"
            lines.append(f"- ⚠️ Zweck/Architektur (`SV-P3-09` / {pui['kind']} / [{conf_tag}]): {pui['message']}")
    else:
        lines.append("- ✅ Zweck-, Scope- & Architektur-Abgleich (`SV-P3-09`) ohne Befund.")
    if report.get("consistency_issues"):
        for ci in report["consistency_issues"]:
            lines.append(f"- ⚠️ Versions-/Regel-Konsistenz (`SV-P3-10` / {ci.get('kind', 'consistency')}): {ci['message']}")
    else:
        lines.append("- ✅ Versions- & Regel-Konsistenz (`SV-P3-10`) ohne Befund.")
    if report.get("spec_issues"):
        for spi in report["spec_issues"]:
            icon = "❌" if spi.get("severity") == "p2" else "⚠️"
            lines.append(f"- {icon} `agentskills.io` [{spi['severity'].upper()} / {spi['kind']}]: {spi['message']}")
    else:
        lines.append("- ✅ `agentskills.io`-Spec-Prüfung (Name, Kompatibilität, Felder) ohne Befund.")
    cont = report.get("contamination") or {}
    if cont.get("flagged"):
        fams = ", ".join(cont.get("application_families", []))
        lines.append(f"- ⚠️ Cross-Language-Contamination (`SV-P3-06`): mehrere unverbundene Sprachfamilien in `SKILL.md` ({fams}).")
    else:
        lines.append("- ✅ Keine Cross-Language-Contamination in `SKILL.md`.")
    if report.get("prose_workflow_issues"):
        for pwi in report["prose_workflow_issues"]:
            lines.append(f"- ⚠️ SKILL-Qualität [{pwi['kind']}]: {pwi['message']}")
    else:
        lines.append("- ✅ Keine README-Tier-Sektionen oder fehlenden Verifikationshinweise in `SKILL.md`.")
    if report["duplicate_pairs"]:
        for dp in report["duplicate_pairs"]:
            lines.append(
                f"- `{dp['file_a']}` ↔ `{dp['file_b']}`: {dp['shared_long_lines']} identische Zeilen"
            )
    else:
        lines.append("- ✅ Keine starken Datei-Duplikate.")

    lines.extend(["", f"## 7. Hygiene ({report['mode']})", ""])
    for k, v in hyg.items():
        lines.append(f"- {'✅' if v else '❌'} `{k}`")
    for jf in report["junk_files"]:
        lines.append(f"- ❌ Bytecode/Junk: `{jf}`")
    for fni in report["frontmatter_file_names_issues"]:
        lines.append(f"- ❌ {fni}")
    for ei in report["evals_issues"]:
        lines.append(f"- ❌ {ei}")
    for eqi in report.get("evals_quality_issues", []):
        lines.append(f"- ⚠️ Eval-Qualität [{eqi['kind']}]: {eqi['message']}")

    return "\n".join(lines) + "\n"


def render_report_draft(report: dict[str, object]) -> str:
    """Erzeugt einen vorbefüllten Entwurf nach BERICHT_VORLAGE.md."""
    name = pathlib.Path(str(report["target"])).name
    fm = report["frontmatter"]
    s = report["summary"]
    purpose = report.get("purpose") or {}
    cov = report.get("security_coverage") or {}
    ver = fm.get("version") or "?"
    unclosed_n = len(s["unclosed_code_blocks"])
    sec_n = int(s.get("unicode_smuggling_issue_count", 0)) + int(s.get("script_security_issue_count", 0))
    orphan_n = int(s.get("orphan_file_count", 0))
    safety_suffix = "" if s["safety_clause_present"] else " *(nur bei sicherheitskritischen Domänen erforderlich)*"
    p_name = purpose.get("name") or name
    p_domain = purpose.get("inferred_domain") or "allgemein"
    p_desc = str(purpose.get("description") or "<keine description im Frontmatter>").replace("|", "\\|").replace("\n", " ")
    if len(p_desc) > 220:
        p_desc = p_desc[:217] + "..."
    p_neg = (
        f"✅ `{str(purpose.get('negative_boundary_excerpt') or '').replace('|', '/')}`"
        if purpose.get("has_negative_boundary")
        else "⚠️ keine explizite Negativ-Abgrenzung erkannt"
    )
    p_scripts = "ja (`scripts/` vorhanden)" if purpose.get("has_bundled_scripts") else "nein (reiner Prompt-/Doku-Skill)"
    purpose_issues = report.get("purpose_issues") or []
    p_check = "✅ unauffällig (`[Verifiziert]`)" if not purpose_issues else f"⚠️ {len(purpose_issues)} Hinweis(e) (siehe P3)"
    p_clarify = (
        "⚠️ Rückfrage an Nutzer empfohlen (Zweck/Domäne mehrdeutig)"
        if purpose.get("needs_user_clarification")
        else "✅ Keine Rückfrage nötig (Zweck & Abgrenzung eindeutig)"
    )
    lines = [
        f"# Verbesserungsanalyse: `{name}` (v{ver})",
        "",
        f"**Fazit:** <Kurzurteil ergänzen>. Automatisch gefunden: **{sec_n} Security-/Unicode-Befunde**, "
        f"**{s['broken_link_count']} kaputte Links/Anker**, **{unclosed_n} ungeschlossene Codeblöcke**, "
        f"**{s['mermaid_issue_count']} Mermaid-Befunde**, **{s['format_issue_count']} Formatierungsfehler**, "
        f"**{s['dead_local_reference_count']} tote lokale Verweise** und **{orphan_n} verwaiste Dateien** "
        f"(MD ≈ {s['total_approx_tokens']:,} Tokens, Bundle {s['bundle_total_bytes']:,} Bytes). Fachliche Prüfung (P1) siehe unten.",
        "",
        "> [!IMPORTANT]",
        "> **Diagnose-Sicherheit:** Jeder Befund ist als **`[Verifiziert]`** (deterministisch per Skript, AST, Link-Check oder Reproduktion bestätigt) oder **`[Heuristik / Verdacht]`** (vor Eingriff manuell zu prüfen) gekennzeichnet.",
        "",
        "## Zweck, Scope & Ziel-Domäne (verifiziert vor Architektur-Bewertung)",
        "",
        "| Dimension | Befund aus `SKILL.md` / Repository |",
        "|---|---|",
        f"| **Name & Modus** | `{p_name}` (`{report['mode']}`) |",
        f"| **Ziel-Domäne (Heuristik)** | `{p_domain}` *(fachlich verifizieren)* |",
        f"| **Kernzweck (`description`)** | {p_desc} |",
        f"| **Trigger-Abgrenzung (`Don't use`)** | {p_neg} |",
        f"| **Mitgelieferte Skripte** | {p_scripts} |",
        f"| **Claim-vs.-Reality & Widerspruchs-Check (`SV-P3-09`)** | {p_check} |",
        f"| **Rückfrage-Gate (Clarification Gate)** | {p_clarify} |",
        "",
        "## Bestandsaufnahme (Größe ≈ Tokens)",
        "",
        "| Datei | Zeichen | ≈ Tokens | Zeilen | TOC |",
        "|---|---:|---:|---:|:---:|",
    ]
    for item in report["inventory"]:
        lines.append(
            f"| `{item['file']}` | {item['chars']:,} | ~{item['approx_tokens']:,} | "
            f"{item['lines']} | {'✅' if item['has_toc'] else '❌'} |"
        )

    budget_note = (
        "Gesamtgröße unter 15k Tokens — nach Anti-Over-Engineering-Regel kein Split und kein TOC erforderlich."
        if int(s["total_approx_tokens"]) < 15_000
        else f"Gesamtgröße ≈ {s['total_approx_tokens']:,} Tokens — größte Dateien/Abschnitte unten auf Split-/TOC-Bedarf prüfen."
    )
    lines.extend(
        [
            "",
            f"- **Security-Scan-Coverage:** {cov.get('scanned_count', s.get('security_scanned_files', 0))} Dateien geprüft, "
            f"{cov.get('skipped_count', s.get('security_skipped_files', 0))} übersprungen.",
            "",
            "> [!NOTE]",
            f"> {budget_note}",
            "",
            "---",
            "",
            "## 🔴 Priorität 1: Fachliche Fehler, Bugs & Security (verifiziert)",
            "",
            "| # | Fundstelle (`Datei:Zeile`) | Konkreter Nachweis (Evidenz/Snippet) | Problem & Auswirkung (inkl. Regel-ID) | Diagnose-Sicherheit | Korrekturvorschlag | Regressionstest |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    p1_rows: list[str] = []
    sandbox_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "sandbox-anti-pattern"]
    for sh in sandbox_hits:
        p1_rows.append(
            f"| F{len(p1_rows) + 1} | `{sh['file']}:{sh['line']}` | `{sh['snippet']}` | Sandbox-Anti-Pattern (`SV-P1-03`): schlägt in Container ohne root fehl | `[Verifiziert]` | Auf User-Space-Tool (`uv`/`venv`/`npm`) umstellen | `skill_audit.py --fail-on p1` |"
        )
    for ui in [x for x in report.get("unicode_smuggling_issues", []) if x.get("severity") == "p1"]:
        p1_rows.append(
            f"| F{len(p1_rows) + 1} | `{ui['file']}:{ui['line']}` | `{ui['codepoint']}` (`{ui['snippet']}`) | Unicode-Smuggling (`SV-P1-04` / {ui['kind']}): versteckte Prompt-Manipulation | `[Verifiziert]` | Unsichtbare Steuer-/Bidi-Zeichen entfernen | `skill_audit.py --fail-on p1` |"
        )
    for si in [x for x in report.get("script_security_issues", []) if x.get("severity") == "p1"]:
        conf_label = "`[Verifiziert]`" if si.get("confidence", "verified") == "verified" else "`[Heuristik / Verdacht]`"
        p1_rows.append(
            f"| F{len(p1_rows) + 1} | `{si['file']}:{si['line']}` | `{si['snippet']}` | Security `{si['kind']}` (`SV-P1-05/06`): {si['message']} | {conf_label} | Sichere Alternative verwenden oder Secret entfernen | `skill_audit.py --fail-on p1` |"
        )
    if p1_rows:
        lines.extend(p1_rows)
    else:
        lines.append("| F1 | `<datei>#L<z>` | `<exaktes Snippet>` | <Problem & Auswirkung> | `[Verifiziert]` | <konkrete Korrektur> | `skill_audit.py --fail-on p1` |")

    lines.extend(["", "## 🟠 Priorität 2: Ausführbarkeit, Links, Orphans & Formatierung"])
    for bl in report["broken_links"]:
        lines.append(f"- Defekter Link (`[Verifiziert]`): `{bl['file']}:{bl['line']}` → `{bl['link']}` ({bl['reason']})")
    if s["unclosed_code_blocks"]:
        lines.append(f"- Ungeschlossene Codeblöcke (`[Verifiziert]`): {', '.join(f'`{f}`' for f in s['unclosed_code_blocks'])}")
    for mi in report["mermaid_issues"]:
        lines.append(f"- Mermaid-Lint (`[Verifiziert]`) `{mi['file']}:{mi['line']}` [{mi['kind']}]: {mi['snippet']}")
    for fi in report["format_issues"][:15]:
        lines.append(f"- Format-Lint (`[Verifiziert]`) `{fi['file']}:{fi['line']}` [{fi['kind']}]: `{fi['snippet']}`")
    if report["dead_local_references"]:
        refs = ", ".join(f"`{d['reference']}`" for d in report["dead_local_references"])
        lines.append(f"- Tote lokale Verweise (`[Verifiziert]`): {refs}")
    for of in report.get("orphan_files", []):
        lines.append(f"- Verwaiste Datei (Orphan, `[Verifiziert]`): `{of['file']}`")
    for spi in [x for x in report.get("spec_issues", []) if x.get("severity") == "p2"]:
        lines.append(f"- `agentskills.io`-Spec (`[Verifiziert]`) [{spi['kind']}]: {spi['message']}")
    for ui in [x for x in report.get("unicode_smuggling_issues", []) if x.get("severity") == "p2"]:
        lines.append(f"- Unsichtbares Unicode-Zeichen (`[Verifiziert]`) `{ui['file']}:{ui['line']}`: {ui['codepoint']} ({ui['name']})")
    for si in [x for x in report.get("script_security_issues", []) if x.get("severity") == "p2"]:
        lines.append(f"- P2-Security-Befund (`[Verifiziert]`) `{si['file']}:{si['line']}` [{si['kind']}]: {si['message']}")
    for pli in report.get("process_lifecycle_issues", []):
        conf_label = "`[Verifiziert]`" if pli.get("confidence", "verified") == "verified" else "`[Heuristik / Verdacht]`"
        lines.append(f"- Prozess-Lifecycle (`SV-P2-12`, {conf_label}) `{pli['file']}:{pli['line']}` [{pli['kind']}]: {pli['message']}")
    for fni in report["frontmatter_file_names_issues"]:
        lines.append(f"- Frontmatter `file_names` (`[Verifiziert]`): {fni}")
    if report["junk_files"]:
        lines.append(f"- Bytecode/Junk im Ordner (`[Verifiziert]`): {', '.join(f'`{j}`' for j in report['junk_files'][:10])}")
    if not (
        report["broken_links"]
        or s["unclosed_code_blocks"]
        or report["mermaid_issues"]
        or report["format_issues"]
        or report["dead_local_references"]
        or report.get("orphan_files")
        or any(x.get("severity") == "p2" for x in report.get("spec_issues", []))
        or any(x.get("severity") == "p2" for x in report.get("unicode_smuggling_issues", []))
        or any(x.get("severity") == "p2" for x in report.get("script_security_issues", []))
        or report.get("process_lifecycle_issues")
        or report["frontmatter_file_names_issues"]
        or report["junk_files"]
    ):
        lines.append("- ✅ Automatisch keine Link-, Codeblock-, Mermaid-, Format-, Verweis-, Orphan-, Spec- oder Junk-Fehler gefunden.")

    lines.extend(
        [
            "",
            "## 🟡 Priorität 3: Struktur, Effizienz & Plattform-Tauglichkeit",
            f"- Frontmatter `description`: {fm.get('description_len')} Zeichen (≤1024: {fm.get('description_within_1024')}, "
            f"EN-Trigger: {fm.get('bilingual_en_trigger')}, DE+EN: {fm.get('bilingual_de_en')})",
            f"- Sicherheits-/Ethik-Schranke: {s['safety_clause_present']} ({s['safety_clause_note']}){safety_suffix}",
        ]
    )
    for pui in report.get("purpose_issues", []):
        conf_label = "`[Verifiziert]`" if pui.get("confidence", "verified") == "verified" else "`[Heuristik / Verdacht]`"
        lines.append(f"- Zweck-/Architektur-Hinweis (`SV-P3-09` / {pui['kind']} / {conf_label}): {pui['message']}")
    for ci in report.get("consistency_issues", []):
        lines.append(f"- Versions-/Regel-Konsistenz (`SV-P3-10` / {ci.get('kind', 'consistency')} / `[Verifiziert]`): {ci['message']}")
    for bw in report["budget_warnings"]:
        lines.append(f"- Budget-Hinweis: {bw}")
    for ph in [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "hardcoded-platform-path"]:
        lines.append(f"- Hardcoded Plattform-Pfad `{ph['file']}:{ph['line']}`: `{ph['snippet']}`")
    for spi in [x for x in report.get("spec_issues", []) if x.get("severity") == "p3"]:
        lines.append(f"- `agentskills.io`-Spec-Hinweis [{spi['kind']}]: {spi['message']}")
    if (report.get("contamination") or {}).get("flagged"):
        fams = ", ".join(report["contamination"].get("application_families", []))  # type: ignore[union-attr]
        lines.append(f"- Cross-Language-Contamination in `SKILL.md`: {fams}")
    for pwi in report.get("prose_workflow_issues", []):
        lines.append(f"- SKILL-Qualität [{pwi['kind']}]: {pwi['message']}")
    if report["duplicate_pairs"]:
        for dp in report["duplicate_pairs"]:
            lines.append(
                f"- Duplikat-Verdacht: `{dp['file_a']}` ↔ `{dp['file_b']}` ({dp['shared_long_lines']} identische lange Zeilen)"
            )
    if report["section_breakdowns"]:
        top_entries = []
        for fname, secs in report["section_breakdowns"].items():
            if secs:
                top = secs[0]
                top_entries.append(f"`{fname}` → {top['heading']} (~{top['approx_tokens']:,} Tokens)")
        if top_entries:
            lines.append(f"- Größte Abschnitte: {'; '.join(top_entries[:5])}")

    lines.extend(
        [
            "",
            "## 🔵 Priorität 4: Qualitätssicherung & Hygiene",
            "",
            "| Maßnahme | Status |",
            "|---|:---:|",
        ]
    )
    for k, v in report["hygiene"].items():
        lines.append(f"| `{k}` | {'✅ vorhanden' if v else '❌ fehlt/fehlerhaft'} |")
    for ei in report["evals_issues"]:
        lines.append(f"- ❌ Eval-Problem: {ei}")
    for eqi in report.get("evals_quality_issues", []):
        lines.append(f"- ⚠️ Eval-Qualität [{eqi['kind']}]: {eqi['message']}")

    lines.extend(
        [
            "",
            "---",
            "",
            "## Empfohlene Umsetzungsreihenfolge",
            "",
            "```mermaid",
            "flowchart LR",
            '  A["P1: Fehler & Bugs"] --> B["P2: Tools, Links & Format"]',
            '  B --> C["P3: Effizienz, Struktur & Cross-Platform"]',
            '  C --> D["P4: Evals, Tests, Hygiene & Version"]',
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        # 1. SKILL.md mit Flow-Multiline YAML, Inline-Liste, Inline-Kommentar, CRLF, Links mit Klammern & Titel
        (root / "SKILL.md").write_text(
            "---\r\n"
            "name: test-skill # kommentar\r\n"
            "description: Kurzer mehrzeiliger Test für Deutsch.\r\n"
            "  Use after pushing commits to test triggers.\r\n"
            "file_names: [references/guide.md, references/missing_in_fm.md]\r\n"
            "metadata:\r\n"
            "  version: 1.3-DE # version comment\r\n"
            "---\r\n"
            "# Titel\r\n\r\n"
            "```inline triple backtick am Zeilenanfang```\r\n"
            "Beispiel im Inline-Code darf keinen Fehlalarm werfen: `<!-- TOC_START -->`, `:**Wort`, `),Wort`.\r\n"
            "Zielprojekt-Manifeste wie `package.json`, `pnpm-lock.yaml` und Systempfade wie `/home/antigravity/env.sh` sind keine toten Skill-Skripte.\r\n"
            "```bash\r\n"
            "sudo apt-get install -y jq\r\n"
            "python3 ~/.gemini/skills/hardcoded/run.py\r\n"
            "```\r\n"
            "```mermaid\r\n"
            "flowchart LR\r\n"
            "  A[Label (Unquoted)] --> B[\"Label (Quoted)\"]\r\n"
            "```\r\n"
            "Siehe `missing_tool.py`, `wrong_dir/SKILL.md` und [OK-Link](references/guide.md#sec-1), "
            "[OK-GitHub-Slug](references/guide.md#phase-1--ziel-modus), "
            "[OK-Link-Heading](references/guide.md#siehe-guide), "
            "[OK-Space](references/my%20file.md), "
            "[OK-Parens](references/foo_(bar).md \"Mein Titel\"), "
            "[OK-Query](references/my%20file.md?raw=1#my-file) sowie [Kaputt](references/nope.md) und [Kaputt-Anker](#gibt-es-nicht).\r\n"
            "**Fett:**Echter Fehler mit Trailing Space.   \r\n",
            encoding="utf-8",
        )
        (root / "references").mkdir()
        (root / "references/my file.md").write_text("# My File\n", encoding="utf-8")
        (root / "references/foo_(bar).md").write_text("# Foo Bar\n", encoding="utf-8")
        long_dup = "Dies ist eine lange identische Testzeile mit ueber hundert Zeichen zur Pruefung der Duplikat-Erkennung in skill_audit."
        dup_block = "\n".join(f"{long_dup} #{i}" for i in range(6)) + "\n"
        # F3: Ungeschlossener ```bash Block gefolgt von einem zweiten geschlossenen ```python Block!
        (root / "references/guide.md").write_text(
            "# Guide\n\n"
            "<!-- TOC_START -->\n"
            "## Inhaltsverzeichnis\n"
            "- [Phase 1 – Ziel-Modus](#sec-1)\n"
            "<!-- TOC_END -->\n\n"
            '<a id="sec-1"></a>\n'
            "## Phase 1 – Ziel-Modus\n"
            "## Siehe [Guide](my%20file.md)\n"
            + dup_block
            + "```bash\n"
            "echo ungeschlossen vor zweitem block\n\n"
            "```python\n"
            "x = 1\n"
            "```\n",
            encoding="utf-8",
        )
        (root / "references/copy.md").write_text("# Copy\n\n" + dup_block, encoding="utf-8")
        # P2: __pycache__ Junk simulieren
        (root / "scripts" / "__pycache__").mkdir(parents=True)
        (root / "scripts" / "__pycache__" / "demo.cpython-311.pyc").write_bytes(b"pyc")
        # P4: evals mit fehlendem Modul, doppelter ID und fehlendem must_contain
        (root / "evals").mkdir()
        (root / "evals/cases.json").write_text(
            json.dumps(
                {
                    "skill_name": "test-skill",
                    "cases": [
                        {
                            "id": "c1",
                            "prompt": "Test 1",
                            "expected_modules": ["SKILL.md", "references/does_not_exist.md"],
                            "must_contain": ["ok"],
                        },
                        {
                            "id": "c1",
                            "prompt": "Test 2",
                            "expected_modules": ["SKILL.md"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        rep = audit_directory(root, include_all_sections=True)
        fm = rep["frontmatter"]
        s = rep["summary"]

        # F1 (v1.3): Flow-Multiline YAML + Inline-List + Inline-Kommentar + CRLF + F5 DE+EN Trigger
        assert fm["name"] == "test-skill", f"F1 Regression (inline comment): {fm}"
        assert fm["version"] == "1.3-DE", f"F1 Regression (nested inline comment): {fm}"
        assert fm["file_names_count"] == 2, f"F1 Regression (inline list): {fm}"
        assert fm["bilingual_en_trigger"] is True, f"F5 Regression (use after): {fm}"
        assert fm["bilingual_de_en"] is True, f"F5 Regression (DE+EN): {fm}"
        assert "Use after pushing" in parse_frontmatter((root / "SKILL.md").read_text())[0]["description"]
        assert s["frontmatter_file_names_issue_count"] == 1, f"P2 file_names Regression: {rep['frontmatter_file_names_issues']}"

        # F3 (v1.3): Ungeschlossener ```bash Block vor ```python Block muss erkannt werden!
        inv_map = {item["file"]: item for item in rep["inventory"]}
        assert inv_map["SKILL.md"]["has_toc"] is False, "B2 Regression: has_toc Fehlalarm auf Backtick-Beispiel!"
        assert inv_map["references/guide.md"]["has_toc"] is True
        assert s["unclosed_code_blocks"] == ["references/guide.md"], f"F3 Regression: {s['unclosed_code_blocks']}"

        # B1 & B3: exactly 1 spacing error + trailing whitespace
        kinds = [fi["kind"] for fi in rep["format_issues"]]
        assert "trailing-whitespace" in kinds, "B1 Regression: Trailing Whitespace nicht erkannt!"
        assert kinds.count("colon-bold-no-space (:**Wort)") == 1, f"B3 Regression: {kinds}"
        assert "paren-comma-no-space (),Wort)" not in kinds, f"B3 Regression: {kinds}"

        # F2 (v1.3): Links mit Klammern & Titel bestehen, exakt 2 kaputte Links; P2: package.json & /home/... ausgeblendet
        assert s["broken_link_count"] == 2, f"F2/B4 Regression: {rep['broken_links']}"
        dead_refs = {d["reference"] for d in rep["dead_local_references"]}
        assert dead_refs == {"missing_tool.py", "wrong_dir/SKILL.md"}, f"P2/L3 Regression: {dead_refs}"

        # P2: __pycache__ erkannt
        assert s["junk_file_count"] == 1 and rep["hygiene"]["no_bytecode_or_junk"] is False, f"P2 Junk Regression: {rep['junk_files']}"

        # P3: Mermaid-Lint + Sandbox-Anti-Pattern + Hardcoded-Pfad erkannt
        assert s["mermaid_issue_count"] == 1, f"P3 Mermaid Regression: {rep['mermaid_issues']}"
        ps_kinds = {x["kind"] for x in rep["portability_and_sandbox_issues"]}
        assert "sandbox-anti-pattern" in ps_kinds, f"P3 Sandbox Regression: {rep['portability_and_sandbox_issues']}"
        assert "hardcoded-platform-path" in ps_kinds, f"P3 Path Regression: {rep['portability_and_sandbox_issues']}"

        # P3: --fail-on Auswertung
        assert len(evaluate_fail_on(rep, "none")) == 0
        assert len(evaluate_fail_on(rep, "p1")) >= 2  # unclosed + sandbox
        assert len(evaluate_fail_on(rep, "p2")) >= 6

        # B5: no false safety trigger
        assert s["safety_clause_present"] is False

        # P4: evals/cases.json fängt fehlendes Modul, doppelte ID und fehlendes must_contain
        assert s["evals_issue_count"] == 3, f"P4 Regression: {rep['evals_issues']}"
        assert rep["hygiene"]["evals/"] is False

        # v1.4: Orphan-File-Erkennung in Basis-Fixture (references/copy.md ist unverlinkt)
        orphan_paths = {o["file"] for o in rep["orphan_files"]}
        assert "references/copy.md" in orphan_paths, f"v1.4 Orphan Regression: {rep['orphan_files']}"

        # F4 + v1.4.1 + v1.5: report draft includes Zweck-vor-Architektur gate, evidence columns, confidence tags & scan coverage
        draft = render_report_draft(rep)
        assert "## Zweck, Scope & Ziel-Domäne" in draft
        assert draft.index("## Zweck, Scope & Ziel-Domäne") < draft.index("## Bestandsaufnahme")
        assert "| Datei | Zeichen | ≈ Tokens | Zeilen | TOC |" in draft
        assert "Security-Scan-Coverage:" in draft
        assert "`[Verifiziert]`" in draft
        assert "| # | Fundstelle (`Datei:Zeile`) | Konkreter Nachweis (Evidenz/Snippet) |" in draft
        assert "Ungeschlossene Codeblöcke" in draft
        assert "Mermaid-Lint" in draft
        assert "Sandbox-Anti-Pattern" in draft
        assert "Duplikat-Verdacht" in draft
        assert "```mermaid" in draft

    # v1.4 / v1.5 End-to-End Integrationstest (Security, Spec, Contamination, Workflow, Evals-Quality, Purpose, Consistency, SARIF)
    with tempfile.TemporaryDirectory() as tmp2:
        root2 = pathlib.Path(tmp2)
        bidi_char = chr(0x202E)
        zw_char = chr(0x200B)
        (root2 / "SKILL.md").write_text(
            "---\n"
            "name: Bad--Name\n"
            "version: 1.0-TEST\n"
            "description: Test skill for integration checks across security, spec, quality and workflow rules. Use when testing v1.5 rules. Don't use for inorganic materials synthesis.\n"
            "custom_extra: true\n"
            "---\n"
            "# Bad Skill\n\n"
            "## Installation\n\n"
            "Run `scripts/tool.py`.\n\n"
            "## Inorganic Materials Synthesis Workflow\n\n"
            "### Step 1\nDo A.\n\n"
            "### Step 2\nDo B.\n\n"
            "### Step 3\nDo C.\n\n"
            f"Hidden bidi {bidi_char} and zero-width {zw_char} test.\n\n"
            "```python\nprint('py')\n```\n"
            "```javascript\nconsole.log('js')\n```\n"
            "```rust\nfn main() {}\n```\n",
            encoding="utf-8",
        )
        (root2 / "scripts").mkdir()
        (root2 / "scripts" / "tool.py").write_text(
            "import subprocess\n"
            "x = " + "ev" + "al('1+1')  #" + " audit-ok\n"
            "subprocess.run('ls', shell=True)\n"
            "p = subprocess.Popen(['echo', 'hi'])\n"
            "tok = '" + "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'\n",
            encoding="utf-8",
        )
        (root2 / "scripts" / "unused_helper.py").write_text("print('orphan')\n", encoding="utf-8")
        (root2 / "evals").mkdir()
        (root2 / "evals" / "cases.json").write_text(
            json.dumps(
                {
                    "skill_name": "Bad--Name",
                    "version": "9.9-MISMATCH",
                    "cases": [
                        {
                            "id": "e1",
                            "prompt": "Check alpha_keyword and beta_keyword please",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["alpha_keyword", "beta_keyword"],
                        },
                        {
                            "id": "e2",
                            "prompt": "Another positive test case",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["something"],
                        },
                        {
                            "id": "e3",
                            "prompt": "Third positive test case",
                            "expected_modules": ["SKILL.md"],
                            "must_contain": ["another"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        rep2 = audit_directory(root2)
        s2 = rep2["summary"]
        assert s2["unicode_smuggling_issue_count"] >= 2, f"v1.5 Unicode E2E failed: {rep2['unicode_smuggling_issues']}"
        assert s2["script_security_issue_count"] >= 4, f"v1.5 Security E2E failed: {rep2['script_security_issues']}"
        assert s2["process_lifecycle_issue_count"] >= 1, f"v1.6 Lifecycle E2E failed: {rep2['process_lifecycle_issues']}"
        assert any(si["kind"] == "unjustified-audit-ok" for si in rep2["script_security_issues"]), rep2["script_security_issues"]
        assert s2["security_scanned_files"] >= 3, rep2["security_coverage"]
        assert any(o["file"] == "scripts/unused_helper.py" for o in rep2["orphan_files"]), rep2["orphan_files"]
        assert any(sp["kind"] == "spec-invalid-name" for sp in rep2["spec_issues"]), rep2["spec_issues"]
        assert s2["contamination_flagged"] is True, rep2["contamination"]
        pw_kinds = {x["kind"] for x in rep2["prose_workflow_issues"]}
        assert "readme-tier-in-skill" in pw_kinds and "workflow-missing-verification" in pw_kinds, pw_kinds
        eq_kinds = {x["kind"] for x in rep2["evals_quality_issues"]}
        assert "eval-no-negative-case" in eq_kinds and "eval-prompt-leakage" in eq_kinds, eq_kinds
        assert s2["purpose_issue_count"] >= 1, f"v1.5 Purpose E2E failed: {rep2['purpose']}"
        assert any(pi["kind"] == "purpose-trigger-contradiction" for pi in rep2["purpose_issues"]), rep2["purpose_issues"]
        assert s2["consistency_issue_count"] >= 1, f"v1.5 Consistency E2E failed: {rep2['consistency_issues']}"

        # Fail-on P1/P2/P3 & SARIF 2.1.0
        assert len(evaluate_fail_on(rep2, "p1")) >= 2
        assert len(evaluate_fail_on(rep2, "p2")) >= 6
        assert len(evaluate_fail_on(rep2, "p3")) >= 10
        sarif = audit_sarif.render_sarif(rep2, tool_version=audit_sarif.TOOL_VERSION)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["version"] == audit_sarif.TOOL_VERSION
        rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        for expected_rid in (
            "SV-P1-04",
            "SV-P1-05",
            "SV-P1-06",
            "SV-P2-03",
            "SV-P2-09",
            "SV-P2-11",
            "SV-P2-12",
            "SV-P3-06",
            "SV-P3-07",
            "SV-P3-08",
            "SV-P3-09",
            "SV-P3-10",
        ):
            assert expected_rid in rule_ids, f"SARIF missing {expected_rid}: {rule_ids}"

    print(
        f"OK: skill_audit.py Selbsttest (alle 42+ Regressionstests v1.3–{audit_sarif.TOOL_VERSION} "
        "inkl. Security, Orphans, Spec, Claim/Contradiction, SSOT-Konsistenz & SARIF) bestanden."
    )
    return 0


def render_rules_table() -> str:
    """Gibt alle 28 stabilen Regel-IDs (SV-P1-01 … SV-P3-10) als Markdown-Tabelle aus."""
    lines = [
        f"# Stabile Audit-Regeln (`skill-verbesserungsanalyse` v{audit_sarif.TOOL_VERSION})",
        "",
        "| Regel-ID | Prio | SARIF-Level | Kategorie | Beschreibung |",
        "|---|:---:|:---:|---|---|",
    ]
    for rid, meta in audit_sarif.RULES.items():
        lines.append(
            f"| `{rid}` | {meta['priority']} | `{meta['level']}` | `{meta['category']}` | {meta['short_description']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Automatisiertes Audit fuer KI-Skills & Wissens-Repos (v{audit_sarif.TOOL_VERSION})"
    )
    parser.add_argument("target", nargs="?", default=".", help="Zielordner des Skills oder Repos")
    parser.add_argument("--json", action="store_true", help="Ausgabe als JSON statt Markdown (inkl. Regel-IDs)")
    parser.add_argument("--sarif", action="store_true", help="Ausgabe als SARIF 2.1.0 JSON (GitHub Code Scanning)")
    parser.add_argument("--rules", action="store_true", help="Alle stabilen Regel-IDs (SV-P1-01...) anzeigen")
    parser.add_argument("--sections", action="store_true", help="Abschnitts-Breakdown fuer alle Markdown-Dateien")
    parser.add_argument("--report-draft", action="store_true", help="Vorbefuellten Bericht nach BERICHT_VORLAGE ausgeben")
    parser.add_argument(
        "--fail-on",
        choices=("none", "p1", "p2", "p3"),
        default="none",
        help="Exit-Code 1 ausgeben, sobald Befunde ab dieser Prioritaet vorliegen (CI-/Validator-Modus)",
    )
    parser.add_argument("--self-test", action="store_true", help="Selbsttest ausfuehren")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.rules:
        print(render_rules_table(), end="")
        return 0

    target_path = pathlib.Path(args.target)
    if not target_path.is_dir():
        print(f"FEHLER: Verzeichnis existiert nicht: {target_path}", file=sys.stderr)
        return 1

    report = audit_directory(target_path, include_all_sections=args.sections)
    if args.sarif:
        print(
            json.dumps(
                audit_sarif.render_sarif(report, tool_version=audit_sarif.TOOL_VERSION),
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.report_draft:
        print(render_report_draft(report))
    else:
        print(render_markdown(report))

    fail_reasons = evaluate_fail_on(report, args.fail_on)
    if fail_reasons:
        print("\nCI-Check fehlgeschlagen (--fail-on " + args.fail_on + "):", file=sys.stderr)
        for r in fail_reasons:
            print(f"  - {r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
