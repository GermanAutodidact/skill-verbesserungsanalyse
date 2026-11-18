#!/usr/bin/env python3
"""Automatisiertes Audit-Skript für KI-Skills, Wissensdatenbanken und Doku-Repos (v1.3-DE).

Misst und prüft:
1. Datei-Inventar (Zeichen, ≈Tokens, Zeilen, max. Zeilenlänge, Überschriften, TOC, LaTeX-Dichte) + Bundle-Budget
2. Abschnitts-Breakdown großer Dateien (>10k Tokens oder --sections)
3. SKILL.md-Frontmatter (name, description <= 1024, DE/EN-Trigger & Zweisprachigkeit, YAML Flow-Multiline/Listen/Block-Scalars, file_names-Abgleich, version)
4. Markdown-Integrität: defekte relative Links (inkl. URL-Decoding, Klammern & Link-Titel), defekte #Anker, ungeschlossene Codeblöcke (auch vor Folgeböcken), Mermaid-Lint, Überlängen (>1500 Z.)
5. Tote lokale Datei-/Skript-Verweise in Backticks (getrennt von Quell-Archiven, Systempfaden & Zielprojekt-Manifesten)
6. Format-Lint (fehlende Leerzeichen & Trailing Whitespace — Codeblöcke/Backticks/LaTeX maskiert!)
7. Portabilität & Sandbox-Anti-Patterns (hardcoded Plattform-Pfade, sudo/apt-get in Shell-Blöcken)
8. Datei-Duplikate (Hinweis auf doppelt gepflegte Gesamtausgaben)
9. Repo-/Skill-Hygiene (Modus A vs. Modus B) inkl. __pycache__/Junk-Prüfung & erweitertem evals/cases.json-Schema
10. Heuristik für Sicherheits-/Ethik-Schranke in SKILL.md + optionaler CI-Exit-Code (--fail-on p1|p2|p3)

Nutzung:
  python3 skill_audit.py <ziel-ordner>                  # Markdown-Report
  python3 skill_audit.py <ziel-ordner> --sections       # inkl. Abschnittsgrößen aller Dateien
  python3 skill_audit.py <ziel-ordner> --report-draft   # Vorbefüllter Entwurf nach BERICHT_VORLAGE.md
  python3 skill_audit.py <ziel-ordner> --fail-on p2     # CI-/Validator-Modus (Exit 1 ab P2-Befund)
  python3 skill_audit.py <ziel-ordner> --json           # JSON-Ausgabe
  python3 skill_audit.py --self-test                    # Erweiterter Selbsttest (25+ Prüfungen)
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

    # Frontmatter, file_names-Abgleich & safety heuristic on SKILL.md
    skill_md = target / "SKILL.md"
    frontmatter_report: dict[str, object] = {"exists": skill_md.is_file()}
    frontmatter_file_names_issues: list[str] = []
    safety_present = False
    safety_note = "SKILL.md nicht vorhanden"
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

    # Evals schema & expected_modules validation
    evals_issues = validate_evals(target, all_files, all_basenames)

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

    return {
        "target": str(target),
        "mode": "git-repo" if is_git_repo else "skill-folder",
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
            "broken_link_count": len(broken_links),
            "unclosed_code_blocks": unclosed_code_blocks,
            "mermaid_issue_count": len(mermaid_issues),
            "portability_and_sandbox_issue_count": len(portability_and_sandbox_issues),
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
        "inventory": inventory,
        "section_breakdowns": section_breakdowns,
        "broken_links": broken_links[:50],
        "mermaid_issues": mermaid_issues[:30],
        "portability_and_sandbox_issues": portability_and_sandbox_issues[:30],
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


def evaluate_fail_on(report: dict[str, object], threshold: str) -> list[str]:
    """Ermittelt CI-Fehlergründe für --fail-on (none|p1|p2|p3)."""
    if threshold == "none":
        return []
    s = report["summary"]
    fm = report["frontmatter"]
    reasons: list[str] = []

    # P1: Struktur-/Ausführungsblocker (ungeschlossene Codeblöcke, ungültiges Evals-JSON, Sandbox-Anti-Patterns)
    if s["unclosed_code_blocks"]:
        reasons.append(f"P1: Ungeschlossene Codeblöcke in {', '.join(s['unclosed_code_blocks'])}")
    if any("Ungültiges JSON" in str(ei) for ei in report["evals_issues"]):
        reasons.append("P1: Ungültiges JSON in evals/cases.json")
    sandbox_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "sandbox-anti-pattern"]
    if sandbox_hits:
        reasons.append(f"P1: {len(sandbox_hits)} Sandbox-Anti-Pattern(s) (sudo/apt-get) in Shell-Blöcken")
    if threshold == "p1":
        return reasons

    # P2: Defekte Links, tote lokale Verweise, Format-Lint, Mermaid-Lint, Evals-Schema, Junk, file_names
    if s["broken_link_count"]:
        reasons.append(f"P2: {s['broken_link_count']} defekte Links/Anker")
    if s["dead_local_reference_count"]:
        reasons.append(f"P2: {s['dead_local_reference_count']} tote lokale Verweise")
    if s["format_issue_count"]:
        reasons.append(f"P2: {s['format_issue_count']} Formatierungsfehler")
    if s["mermaid_issue_count"]:
        reasons.append(f"P2: {s['mermaid_issue_count']} Mermaid-Lint-Befunde")
    if s["evals_issue_count"]:
        reasons.append(f"P2: {s['evals_issue_count']} Eval-Schema-Fehler")
    if s["frontmatter_file_names_issue_count"]:
        reasons.append(f"P2: {s['frontmatter_file_names_issue_count']} fehlerhafte Frontmatter-file_names")
    if s["junk_file_count"]:
        reasons.append(f"P2: {s['junk_file_count']} Bytecode-/Junk-Dateien (__pycache__/.pyc/.DS_Store)")
    if threshold == "p2":
        return reasons

    # P3: Frontmatter-Limits/Trigger, Hardcoded-Pfade, Budget-Warnungen
    if fm.get("exists"):
        if not fm.get("description_within_1024"):
            reasons.append("P3: SKILL.md description fehlt oder > 1024 Zeichen")
        if not fm.get("bilingual_en_trigger"):
            reasons.append("P3: Englischer Trigger in SKILL.md description fehlt")
    path_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "hardcoded-platform-path"]
    if path_hits:
        reasons.append(f"P3: {len(path_hits)} hardcoded Plattform-Pfade")
    if s["budget_warning_count"]:
        reasons.append(f"P3: {s['budget_warning_count']} Budget-/TOC-Warnungen")
    return reasons


def render_markdown(report: dict[str, object]) -> str:
    s = report["summary"]
    fm = report["frontmatter"]
    hyg = report["hygiene"]
    safety_suffix = "" if s["safety_clause_present"] else " *(nur bei sicherheitskritischen Domänen erforderlich)*"
    lines = [
        f"# Automatisierter Skill-Audit: `{pathlib.Path(str(report['target'])).name}` ({report['mode']})",
        "",
        "## 1. Kennzahlen & Frontmatter",
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

    lines.extend(["", "## 4. Tote lokale Datei-/Skript-Verweise in Backticks", ""])
    if report["dead_local_references"]:
        for d in report["dead_local_references"]:
            lines.append(f"- `{d['reference']}` (erwähnt in: {', '.join(d['mentioned_in'])})")
    else:
        lines.append("- ✅ Keine toten lokalen Datei-Verweise gefunden.")
    if s["external_or_archive_reference_count"]:
        lines.append(
            f"- ℹ️ Zusätzlich {s['external_or_archive_reference_count']} externe/Zielprojekt-/Quell-Archiv-Pfade ausgeblendet."
        )

    lines.extend(["", "## 5. Format-Lint, Portabilität & Sandbox-Checks", ""])
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
    if report["long_lines"]:
        for ll in report["long_lines"][:10]:
            lines.append(f"- ℹ️ Überlange Zeile (>1.500 Z.): `{ll['file']}:{ll['line']}` ({ll['length']:,} Zeichen)")

    lines.extend(["", "## 6. Duplikat-Paare (≥5 identische lange Zeilen)", ""])
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

    return "\n".join(lines) + "\n"


def render_report_draft(report: dict[str, object]) -> str:
    """Erzeugt einen vorbefüllten Entwurf nach BERICHT_VORLAGE.md."""
    name = pathlib.Path(str(report["target"])).name
    fm = report["frontmatter"]
    s = report["summary"]
    ver = fm.get("version") or "?"
    unclosed_n = len(s["unclosed_code_blocks"])
    safety_suffix = "" if s["safety_clause_present"] else " *(nur bei sicherheitskritischen Domänen erforderlich)*"
    lines = [
        f"# Verbesserungsanalyse: `{name}` (v{ver})",
        "",
        f"**Fazit:** <Kurzurteil ergänzen>. Automatisch gefunden: **{s['broken_link_count']} kaputte Links/Anker**, "
        f"**{unclosed_n} ungeschlossene Codeblöcke**, **{s['mermaid_issue_count']} Mermaid-Befunde**, "
        f"**{s['format_issue_count']} Formatierungsfehler** und **{s['dead_local_reference_count']} tote lokale Verweise** "
        f"(MD ≈ {s['total_approx_tokens']:,} Tokens, Bundle {s['bundle_total_bytes']:,} Bytes). Fachliche Prüfung (P1) siehe unten.",
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
            "> [!NOTE]",
            f"> {budget_note}",
            "",
            "---",
            "",
            "## 🔴 Priorität 1: Fachliche Fehler & Bugs (manuell verifiziert)",
            "",
            "| # | Fundstelle | Problem | Korrektur |",
            "|---|---|---|---|",
        ]
    )
    sandbox_hits = [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "sandbox-anti-pattern"]
    if sandbox_hits:
        for idx, sh in enumerate(sandbox_hits, 1):
            lines.append(
                f"| F{idx} | `{sh['file']}:{sh['line']}` | Sandbox-Anti-Pattern (`{sh['snippet']}`) | Auf User-Space-Tool (`uv`/`venv`/`npm`) umstellen |"
            )
    else:
        lines.append("| F1 | `<datei>#L<z>` | <verifizierter Befund> | <konkrete Korrektur> |")

    lines.extend(["", "## 🟠 Priorität 2: Ausführbarkeit, Links & Formatierung"])
    for bl in report["broken_links"]:
        lines.append(f"- Defekter Link: `{bl['file']}:{bl['line']}` → `{bl['link']}` ({bl['reason']})")
    if s["unclosed_code_blocks"]:
        lines.append(f"- Ungeschlossene Codeblöcke: {', '.join(f'`{f}`' for f in s['unclosed_code_blocks'])}")
    for mi in report["mermaid_issues"]:
        lines.append(f"- Mermaid-Lint `{mi['file']}:{mi['line']}` [{mi['kind']}]: {mi['snippet']}")
    for fi in report["format_issues"][:15]:
        lines.append(f"- Format-Lint `{fi['file']}:{fi['line']}` [{fi['kind']}]: `{fi['snippet']}`")
    if report["dead_local_references"]:
        refs = ", ".join(f"`{d['reference']}`" for d in report["dead_local_references"])
        lines.append(f"- Tote lokale Verweise: {refs}")
    for fni in report["frontmatter_file_names_issues"]:
        lines.append(f"- Frontmatter `file_names`: {fni}")
    if report["junk_files"]:
        lines.append(f"- Bytecode/Junk im Ordner: {', '.join(f'`{j}`' for j in report['junk_files'][:10])}")
    if not (
        report["broken_links"]
        or s["unclosed_code_blocks"]
        or report["mermaid_issues"]
        or report["format_issues"]
        or report["dead_local_references"]
        or report["frontmatter_file_names_issues"]
        or report["junk_files"]
    ):
        lines.append("- ✅ Automatisch keine Link-, Codeblock-, Mermaid-, Format-, Verweis- oder Junk-Fehler gefunden.")

    lines.extend(
        [
            "",
            "## 🟡 Priorität 3: Struktur, Effizienz & Plattform-Tauglichkeit",
            f"- Frontmatter `description`: {fm.get('description_len')} Zeichen (≤1024: {fm.get('description_within_1024')}, "
            f"EN-Trigger: {fm.get('bilingual_en_trigger')}, DE+EN: {fm.get('bilingual_de_en')})",
            f"- Sicherheits-/Ethik-Schranke: {s['safety_clause_present']} ({s['safety_clause_note']}){safety_suffix}",
        ]
    )
    for bw in report["budget_warnings"]:
        lines.append(f"- Budget-Hinweis: {bw}")
    for ph in [x for x in report["portability_and_sandbox_issues"] if x["kind"] == "hardcoded-platform-path"]:
        lines.append(f"- Hardcoded Plattform-Pfad `{ph['file']}:{ph['line']}`: `{ph['snippet']}`")
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

        # F4: report draft includes all sections
        draft = render_report_draft(rep)
        assert "| Datei | Zeichen | ≈ Tokens | Zeilen | TOC |" in draft
        assert "Ungeschlossene Codeblöcke" in draft
        assert "Mermaid-Lint" in draft
        assert "Sandbox-Anti-Pattern" in draft
        assert "Duplikat-Verdacht" in draft
        assert "```mermaid" in draft

    print("OK: skill_audit.py Selbsttest (alle 25+ Regressionstests F1–F5, B1–B6, L1–L3, P2–P4) bestanden.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatisiertes Audit fuer KI-Skills & Wissens-Repos (v1.3)")
    parser.add_argument("target", nargs="?", default=".", help="Zielordner des Skills oder Repos")
    parser.add_argument("--json", action="store_true", help="Ausgabe als JSON statt Markdown")
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

    target_path = pathlib.Path(args.target)
    if not target_path.is_dir():
        print(f"FEHLER: Verzeichnis existiert nicht: {target_path}", file=sys.stderr)
        return 1

    report = audit_directory(target_path, include_all_sections=args.sections)
    if args.json:
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
