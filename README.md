# `skill-verbesserungsanalyse` (v1.4-DE)

Strukturierte **Verbesserungsanalyse (Audit → Bericht → Umsetzung)** als portabler KI-Skill für **KI-Skills (`SKILL.md`), Prompts, Wissensdatenbanken und Dokumentations-Repos** — vollständig **Zero-Dependency** (Python 3.10+ Standardbibliothek).

Das Paket kombiniert das deterministische Audit-Skript ([`scripts/skill_audit.py`](scripts/skill_audit.py)) mit modularen Security-, Qualitäts- & SARIF-Scannern, einem idempotenten TOC-/Anker-Generator ([`scripts/add_toc.py`](scripts/add_toc.py)), einem domänenübergreifenden Prüfkatalog ([`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md)) sowie einer standardisierten Berichtsvorlage ([`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md)) nach dem Prioritätenmodell **P1–P4**.

## Kernfunktionen

- **Erst messen, dann urteilen:** Vollautomatische Bestandsaufnahme von Zeichen, ≈ Tokens, Bundle-Größe, Abschnittsgrößen (`--sections`) und LaTeX-Dichte.
- **Sicherheit & Integrität ([`scripts/audit_security.py`](scripts/audit_security.py)):**
  - **Unicode-Smuggling & Bidi-Trojan-Source (`CVE-2021-42574`):** Erkennt Unicode-Tags (`U+E0000–U+E007F`), Bidi-Overrides, Zero-Width-Zeichen & unsichtbare Steuerzeichen.
  - **AST-basierter Python- & Shell-Security-Scan:** Prüft gebündelte Skripte via Python `ast` auf `eval`/`exec`/`compile`, `os.system`/`os.popen`, `subprocess(..., shell=True)`, unsichere Deserialisierung (`pickle`/`marshal`), Credential-Pfade (`~/.ssh`, `~/.aws`), gefährliche Shell-Muster (`curl | sh`) sowie Hardcoded Secrets / Private Keys (mit `# audit-ok`-Ausnahmen).
- **Spec-, Struktur- & Qualitäts-Checks ([`scripts/audit_quality.py`](scripts/audit_quality.py)):**
  - **Transitive Orphan-File-Erkennung (BFS ab `SKILL.md`):** Meldet unreferenzierte Dateien in `scripts/`, `references/` und `assets/` (folgt auch Python-Imports transitiv).
  - **`agentskills.io`-Spec-Validierung:** NFKC-`name` (≤ 64 Zeichen, Kleinbuchstaben/Ziffern/Bindestriche, kein `--`, Ordner-Abgleich), `compatibility` (≤ 500 Zeichen) & Hinweis auf Nicht-Standard-Felder.
  - **Cross-Language-Contamination & Workflow-Qualität:** Erkennt unverbundene Programmiersprachen-Familien in `SKILL.md`, README-Tier-Sektionen in `SKILL.md` sowie Multi-Step-Workflows ohne Verifikations-/Exit-Hinweise.
  - **Eval-Qualität & Leakage-Lint:** Prüft `evals/cases.json` auf Negative-Trigger-Abdeckung (`should_trigger: false`) und Prompt-Leakage.
- **Markdown-, Link-, Format- & Hygiene-Lint ([`scripts/skill_audit.py`](scripts/skill_audit.py)):**
  - YAML-Frontmatter-Parser (CRLF, Flow-Multiline, Block-Scalars `>`/`|`, Inline-/Block-Listen, `file_names`-Abgleich, ≤ 1.024 Zeichen, DE+EN-Trigger).
  - Relative Markdown-Links & `#Anker`, ungeschlossene Codeblöcke, Mermaid-Syntax-Lint, tote lokale Verweise, Format-Lint, Sandbox-Anti-Patterns (`sudo`/`apt-get`), Duplikate & `__pycache__`-Hygiene.
- **25 stabile Regel-IDs & SARIF 2.1.0 ([`scripts/audit_sarif.py`](scripts/audit_sarif.py)):**
  - Einheitliche Regel-IDs (`SV-P1-01` … `SV-P3-08`), `--rules`-Übersicht, `--sarif`-Export für GitHub Code Scanning / PR-Annotationen und `--fail-on p1|p2|p3` für CI-Gates.
- **Idempotentes Inhaltsverzeichnis ([`scripts/add_toc.py`](scripts/add_toc.py)):** Erzeugt und aktualisiert `<!-- TOC_START -->`…`<!-- TOC_END -->` mit Zeilenbereichen, schützt Codeblöcke und unterstützt `--check` für CI.
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

# SARIF 2.1.0 Ausgabe (z. B. für GitHub Code Scanning / PR-Annotationen)
python3 scripts/skill_audit.py <ziel-ordner> --sarif > results.sarif

# Maschinenlesbares JSON inkl. stabiler Regel-IDs & Regel-Katalog anzeigen
python3 scripts/skill_audit.py <ziel-ordner> --json
python3 scripts/skill_audit.py --rules

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
python3 scripts/audit_security.py --self-test
python3 scripts/audit_quality.py --self-test
python3 scripts/audit_sarif.py --self-test
python3 scripts/skill_audit.py --self-test
python3 scripts/skill_audit.py . --fail-on p2
```

## Struktur

| Pfad | Zweck |
|---|---|
| [`SKILL.md`](SKILL.md) | Kern-Workflow (Phasen 1–5), Grundregeln & Priorisierungs-Matrix (P1–P4) |
| [`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md) | Qualitativer Prüfkatalog (Kategorien A–G) |
| [`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md) | Standardisierte Vorlage für Verbesserungsanalyse-Berichte |
| [`scripts/skill_audit.py`](scripts/skill_audit.py) | Haupt-CLI, Orchestrierung, Markdown/JSON/SARIF-Ausgabe & CI-Validator |
| [`scripts/audit_security.py`](scripts/audit_security.py) | Unicode-Smuggling-, Bidi-, AST-Skript-Security- & Secret-Scanner |
| [`scripts/audit_quality.py`](scripts/audit_quality.py) | BFS-Orphan-Erkennung, `agentskills.io`-Spec, Contamination, Workflow- & Eval-Lint |
| [`scripts/audit_sarif.py`](scripts/audit_sarif.py) | Stabile Regel-Registry (`SV-P1-01`…`SV-P3-08`) & SARIF-2.1.0-Exporter |
| [`scripts/add_toc.py`](scripts/add_toc.py) | Idempotenter TOC- & Anker-Generator (`--check`, `--self-test`) |
| [`evals/cases.json`](evals/cases.json) | Evaluierungs- & Regressionsfälle (10 Szenarien inkl. Negative-Trigger) |

## Lizenz

MIT License — siehe [`LICENSE`](LICENSE) und [`NOTICE.md`](NOTICE.md).
