# `skill-verbesserungsanalyse` (v1.5-DE)

Strukturierte **Verbesserungsanalyse (Audit → Bericht → Umsetzung)** als portabler KI-Skill für **KI-Skills (`SKILL.md`), Prompts, Wissensdatenbanken und Dokumentations-Repos** — vollständig **Zero-Dependency** (Python 3.10+ Standardbibliothek).

Das Paket kombiniert das deterministische Audit-Skript ([`scripts/skill_audit.py`](scripts/skill_audit.py)) mit modularen Security-, Qualitäts- & SARIF-Scannern, einem idempotenten TOC-/Anker-Generator ([`scripts/add_toc.py`](scripts/add_toc.py)), einem domänenübergreifenden Prüfkatalog ([`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md)) sowie einer evidenzbasierten Berichtsvorlage ([`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md)) nach dem Prioritätenmodell **P1–P4**.

## Kernfunktionen

- **Semantisches Zweck-vor-Architektur-Gate & Rückfrage-Pflicht (`SV-P3-09`):** Erfasst und verifiziert zuerst Zweck, Beschreibung (`Use when` / `Don't use`) und Ziel-Domäne direkt aus `SKILL.md`, prüft **Anspruch vs. Wirklichkeit (Claim-vs.-Reality)** (existieren die versprochenen Skripte, Referenzen, CLI-Flags und Workflows?) sowie innere **Widersprüche** (`Don't use for X` im Frontmatter vs. Workflow für `X` im Body) und verlangt bei unklarem Scope eine **Rückfrage an den Nutzer (Clarification Gate)**, bevor Architektur-Bewertungen erfolgen.
- **Erst messen, dann urteilen (Evidenz & Diagnose-Sicherheit):** Vollautomatische Bestandsaufnahme von Zeichen, ≈ Tokens, Bundle-Größe, Abschnittsgrößen (`--sections`) und LaTeX-Dichte; strikte Trennung im Bericht zwischen **`[Verifiziert]`** (deterministisch geprüft/reproduziert) und **`[Heuristik / Verdacht]`** (manuell zu bestätigen) inkl. Regressionstest pro Befund.
- **Erweiterte Sicherheit, Scan-Coverage & Begründungspflicht ([`scripts/audit_security.py`](scripts/audit_security.py)):**
  - **Unicode-Smuggling & Bidi-Trojan-Source (`CVE-2021-42574`, `SV-P1-04`):** Erkennt Unicode-Tags (`U+E0000–U+E007F`), Bidi-Overrides, Zero-Width-Zeichen & unsichtbare Steuerzeichen.
  - **Multi-Format-Security- & Secret-Scan (`SV-P1-05`, `SV-P1-06`, `SV-P2-11`):** Prüft `.py`, `.sh`/`.bash`, `.js`/`.ts`, `.ps1`, `.env`, `.toml`, `.yaml`, `.json` und `.md` via Python-`ast` und Musteranalyse auf `eval`/`exec`/`compile`, `os.system`/`os.popen`, `subprocess(..., shell=True)`, unsichere Deserialisierung (`pickle`/`marshal`), Credential-Pfade (`~/.ssh`, `~/.aws`), gefährliche Shell-/PowerShell-Muster (`curl | sh`, `Invoke-Expression`) sowie Hardcoded Secrets / Private Keys.
  - **Scan-Coverage & `# audit-ok: <Begründung>`:** Weist transparent die **Scan-Coverage** (`scanned_files` vs. `skipped_files`) aus und erzwingt für Unterdrückungen eine explizite Begründung (`# audit-ok: <Begründung>` bzw. `// audit-ok: <Begründung>`; ein bloßes `# audit-ok` ohne Begründung wird als P2 gemeldet).
- **Spec-, Struktur-, Konsistenz- & Qualitäts-Checks ([`scripts/audit_quality.py`](scripts/audit_quality.py)):**
  - **Transitive Orphan-File-Erkennung (`SV-P2-03`, BFS ab `SKILL.md`):** Meldet unreferenzierte Dateien in `scripts/`, `references/` und `assets/` (folgt auch Python-Imports transitiv).
  - **`agentskills.io`-Spec-Validierung (`SV-P2-09`, `SV-P3-05`):** NFKC-`name` (≤ 64 Zeichen, Kleinbuchstaben/Ziffern/Bindestriche, kein `--`, Ordner-Abgleich), `compatibility` (≤ 500 Zeichen) & Hinweis auf Nicht-Standard-Felder.
  - **Cross-Language-Contamination, Claim-Alignment & Workflow-Qualität (`SV-P3-06`, `SV-P3-07`, `SV-P3-09`):** Erkennt unverbundene Programmiersprachen-Familien in `SKILL.md`, fehlende `Don't use`-Abgrenzungen, Ghost-Claims (versprochene Skripte/Flags fehlen), Frontmatter/Body-Widersprüche, README-Tier-Sektionen in `SKILL.md` sowie Multi-Step-Workflows ohne Verifikations-/Exit-Hinweise.
  - **Versions- & Regel-Konsistenz (`SV-P3-10`):** Prüft als 27. Regel automatisch, ob Version (`1.5-DE`) und Regel-Anzahl (27 Regeln `SV-P1-01`…`SV-P3-10`) zwischen Code-SSOT, `SKILL.md`, `README.md`, `references/` und `evals/cases.json` synchron sind.
  - **Eval-Qualität & Leakage-Lint (`SV-P3-08`):** Prüft `evals/cases.json` auf Negative-Trigger-Abdeckung (`should_trigger: false`), Adversarial-Rubriken (`verification_rubric`, `must_not_claim`) und Prompt-Leakage.
- **Markdown-, Link-, Format- & Hygiene-Lint ([`scripts/skill_audit.py`](scripts/skill_audit.py)):**
  - YAML-Frontmatter-Parser (CRLF, Flow-Multiline, Block-Scalars `>`/`|`, Inline-/Block-Listen, `file_names`-Abgleich, ≤ 1.024 Zeichen, DE+EN-Trigger).
  - Relative Markdown-Links & `#Anker`, ungeschlossene Codeblöcke, Mermaid-Syntax-Lint, tote lokale Verweise, Format-Lint, Sandbox-Anti-Patterns (`sudo`/`apt-get`), Duplikate & `__pycache__`-Hygiene.
- **27 stabile Regel-IDs & SARIF 2.1.0 ([`scripts/audit_sarif.py`](scripts/audit_sarif.py)):**
  - Einheitliche Regel-IDs (`SV-P1-01` … `SV-P3-10`), `--rules`-Übersicht, `--sarif`-Export für GitHub Code Scanning / PR-Annotationen und `--fail-on p1|p2|p3` für CI-Gates.
- **Kontrollierter Git-Staged-Approval-Workflow & Idempotentes TOC ([`scripts/add_toc.py`](scripts/add_toc.py)):**
  - In Phase 3 strikte Prüfung von `git status --short`, Zusammenfassung von `git diff --stat`, gezieltes Staging (`git add <datei1> <datei2>` statt blindem `git add -A`) und getrennte Freigabe-Schritte für Datei-Edits, Commit und Push.
  - `add_toc.py` erzeugt und aktualisiert `<!-- TOC_START -->`…`<!-- TOC_END -->` mit Zeilenbereichen, schützt Codeblöcke und unterstützt `--check` für CI.
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

# Maschinenlesbares JSON inkl. stabiler Regel-IDs & 27er Regel-Katalog anzeigen
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
| [`SKILL.md`](SKILL.md) | Kern-Workflow (Phasen 1–3), Zweck-/Rückfrage-Gate, Staged-Git-Workflow & Priorisierungs-Matrix (P1–P4) |
| [`references/PRUEFKATALOG.md`](references/PRUEFKATALOG.md) | Qualitativer Prüfkatalog (Vorab-Gate 0 + Kategorien A–G, 27 Regeln `SV-P1-01`…`SV-P3-10`) |
| [`references/BERICHT_VORLAGE.md`](references/BERICHT_VORLAGE.md) | Evidenzbasierte Berichtsvorlage (`[Verifiziert]` vs. `[Heuristik / Verdacht]`, Nachweis & Regressionstest) |
| [`scripts/skill_audit.py`](scripts/skill_audit.py) | Haupt-CLI, Orchestrierung, Markdown/JSON/SARIF-Ausgabe & CI-Validator |
| [`scripts/audit_security.py`](scripts/audit_security.py) | Multi-Format-Security-, Unicode-Smuggling-, Bidi-, AST- & Secret-Scanner inkl. Scan-Coverage & `# audit-ok: <Begründung>` |
| [`scripts/audit_quality.py`](scripts/audit_quality.py) | Claim-vs.-Reality-Abgleich (`SV-P3-09`), Versions-/Regel-SSOT (`SV-P3-10`), BFS-Orphans, `agentskills.io`-Spec, Contamination, Workflow- & Eval-Lint |
| [`scripts/audit_sarif.py`](scripts/audit_sarif.py) | Stabile Regel-Registry (27 Regeln `SV-P1-01`…`SV-P3-10`) & SARIF-2.1.0-Exporter |
| [`scripts/add_toc.py`](scripts/add_toc.py) | Idempotenter TOC- & Anker-Generator (`--check`, `--self-test`) |
| [`evals/cases.json`](evals/cases.json) | Evaluierungs- & Regressionsfälle (12 Szenarien inkl. Negative-Trigger, Zweck-Gate & Adversarial-Claim-Check) |

## Lizenz

MIT License — siehe [`LICENSE`](LICENSE) und [`NOTICE.md`](NOTICE.md).
