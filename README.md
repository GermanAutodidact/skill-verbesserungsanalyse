# `skill-verbesserungsanalyse` (v1.3-DE)

Strukturierte **Verbesserungsanalyse (Audit → Bericht → Umsetzung)** als portabler KI-Skill für **KI-Skills (`SKILL.md`), Prompts, Wissensdatenbanken und Dokumentations-Repos**.

Das Paket kombiniert ein deterministisches Python-Audit-Skript ([`scripts/skill_audit.py`](scripts/skill_audit.py)), einen idempotenten TOC-/Anker-Generator ([`scripts/add_toc.py`](scripts/add_toc.py)), einen domänenübergreifenden Prüfkatalog ([`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md)) sowie eine standardisierte Berichtsvorlage ([`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md)) nach dem Prioritätenmodell **P1–P4**.

## Kernfunktionen

- **Erst messen, dann urteilen:** Vollautomatische Bestandsaufnahme von Zeichen, ≈ Tokens, Bundle-Größe, Abschnittsgrößen (`--sections`) und LaTeX-Dichte.
- **Umfassende Integritäts- & Lint-Checks (`scripts/skill_audit.py`):**
  - YAML-Frontmatter-Parser (CRLF, Flow-Multiline, Block-Scalars `>`/`|`, Inline- & Block-Listen, `file_names`-Abgleich, ≤ 1.024 Zeichen, DE+EN-Trigger).
  - Relative Markdown-Links & `#Anker` (URL-Decoding, Klammern im Dateinamen, Link-Titel, exakte GitHub-Slugs).
  - Ungeschlossene Fenced Code Blocks (auch vor nachfolgenden Codeblöcken) & Mermaid-Syntax-Lint.
  - Tote lokale Datei-/Skript-Verweise (getrennt von Quell-Archiven, Systempfaden & typischen Projekt-Manifesten wie `package.json`).
  - Format-Lint (Leerzeichen & Trailing Whitespace bei maskiertem Code/LaTeX), Portabilität & Sandbox-Anti-Patterns (`sudo`/`apt-get` in Shell-Blöcken, hardcoded Plattform-Pfade).
  - Duplikat-Erkennung, `__pycache__`/Junk-Hygiene, `evals/cases.json`-Schema-Prüfung und CI-Exit-Codes (`--fail-on p1|p2|p3`).
- **Idempotentes Inhaltsverzeichnis (`scripts/add_toc.py`):** Erzeugt und aktualisiert `<!-- TOC_START -->`…`<!-- TOC_END -->` mit Zeilenbereichen, schützt Codeblöcke, löst manuelle TOCs ab und unterstützt `--check` für CI.
- **Anti-Over-Engineering:** Proportionale Empfehlungen — kleine Skills (< 15k Tokens, 1–3 Dateien) werden nicht unnötig aufgesplittet.

## Nutzung (CLI)

```bash
# Vollständiger Markdown-Audit (inkl. Auto-Sections bei Dateien > 10k Tokens)
python3 scripts/skill_audit.py <ziel-ordner>

# Abschnitts-Breakdown für alle Dateien
python3 scripts/skill_audit.py <ziel-ordner> --sections

# Vorbefüllter Berichtsentwurf nach BERICHT_VORLAGE.md
python3 scripts/skill_audit.py <ziel-ordner> --report-draft

# Strenger CI-/Validator-Modus (Exit-Code 1 ab P2-Befund)
python3 scripts/skill_audit.py <ziel-ordner> --fail-on p2

# Idempotentes TOC mit Zeilen-Index erzeugen / in CI prüfen
python3 scripts/add_toc.py <datei.md>
python3 scripts/add_toc.py <datei.md> --check
```

## Installation als KI-Skill

Klone dieses Repository in das jeweilige Skill-Verzeichnis deiner Plattform (z. B. `~/.gemini/skills/skill-verbesserungsanalyse/` für Antigravity oder `~/.claude/skills/skill-verbesserungsanalyse/` für Claude Code):

```bash
git clone https://github.com/GermanAutodidact/skill-verbesserungsanalyse.git <skill-dir>/skill-verbesserungsanalyse
```

## Selbsttests & Validierung

```bash
python3 scripts/add_toc.py --self-test
python3 scripts/skill_audit.py --self-test
python3 scripts/skill_audit.py . --fail-on p2
```

## Struktur

| Pfad | Zweck |
|---|---|
| [`SKILL.md`](SKILL.md) | Kern-Workflow (Phasen 1–5), Grundregeln & Priorisierungs-Matrix (P1–P4) |
| [`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md) | Qualitativer Prüfkatalog (Kategorien A–G) |
| [`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md) | Standardisierte Vorlage für Verbesserungsanalyse-Berichte |
| [`scripts/skill_audit.py`](scripts/skill_audit.py) | Automatisiertes Audit- & CI-Validator-Skript (25+ Selbsttests) |
| [`scripts/add_toc.py`](scripts/add_toc.py) | Idempotenter TOC- & Anker-Generator (`--check`, `--self-test`) |
| [`evals/cases.json`](evals/cases.json) | Evaluierungs- & Regressionsfälle (8 Szenarien) |

## Lizenz

MIT License — siehe [`LICENSE`](LICENSE) und [`NOTICE.md`](NOTICE.md).
