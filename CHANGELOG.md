# Changelog

Alle nennenswerten Änderungen an `skill-verbesserungsanalyse` werden hier dokumentiert.

## [1.5-DE] – 2026-11-18

### Hinzugefügt & Geschärft (v1.5-DE — Semantisches Zweck-Gate, Evidenz & Security-Transparenz)
- **Semantischer Claim-vs.-Reality- & Widerspruchs-Check (`SV-P3-09`) + Rückfrage-Pflicht:** Prüft nicht mehr nur die Existenz von Triggern, sondern gleicht **Anspruch vs. Wirklichkeit (Claim-vs.-Reality)** ab (existieren die in `description` versprochenen Skripte, Referenzen, CLI-Flags und Workflows?) und erkennt innere **Widersprüche** (`Don't use for X` im Frontmatter vs. Anleitung für `X` im Body). Neues **Clarification Gate (Rückfrage-Pflicht)** in `SKILL.md` und `references/PRUEFKATALOG.md`, falls Zweck, Ziel-Domäne oder Scope-Grenzen mehrdeutig/widersprüchlich sind.
- **Versions- & Regel-Konsistenz als 27. Regel (`SV-P3-10`):** Zentrale Single Source of Truth für Version (`1.5-DE`) und Regel-Anzahl (27 stabile Regeln `SV-P1-01`…`SV-P3-10`) mit automatischem Konsistenz-Abgleich zwischen Code-SSOT (`scripts/`), `SKILL.md`, `README.md`, `references/PRUEFKATALOG.md` und `evals/cases.json`.
- **Erweiterte Security-Scan-Coverage & Begründungspflicht (`# audit-ok: <Begründung>`):** Security- und Secret-Scanning deckt `.py`, `.sh`/`.bash`, `.js`/`.ts`, `.ps1`, `.env`, `.toml`, `.yaml`, `.json` und `.md` ab, weist die **Scan-Coverage** (`scanned_files` vs. `skipped_files`) transparent aus und verlangt für Unterdrückungen eine explizite Begründung (`# audit-ok: <Begründung>` / `// audit-ok: <Begründung>`; bloßes `# audit-ok` wird als P2 gemeldet).
- **Kontrollierter Git-Staged-Approval-Workflow (Phase 3):** Verpflichtender Check von `git status --short` vor und nach Edits, Anzeige/Zusammenfassung von `git diff --stat`, gezieltes Staging ausschließlich der geänderten Dateien (`git add <datei1> <datei2>` statt blindem `git add -A`) sowie getrennte Freigabe-Checkpoints für Datei-Änderungen → Git-Commit → Git-Push.
- **Evidenzbasierte Berichtsvorlage (`references/BERICHT_VORLAGE.md`):** Klare Trennung zwischen **`[Verifiziert]`** (deterministisch geprüft/reproduziert) und **`[Heuristik / Verdacht]`** (manuell zu bestätigen) sowie erweitertes P1/P2-Befundschema mit Fundstelle (`Datei:Zeile`), Nachweis/Snippet, Problem & Auswirkung, Diagnose-Sicherheit, Korrekturvorschlag und Regressionstest.
- **Geschärfte Eval-Matrix (`evals/cases.json`):** `eval-11-purpose-before-architecture` um `verification_rubric` und `must_not_claim` erweitert und neuen Adversarial-Testfall `eval-12-adversarial-contradiction-and-ghost-claims` (12 Szenarien insgesamt, 0 % Prompt-Leakage) ergänzt.

## [1.4.1-DE] – 2026-11-18

### Hinzugefügt (Zweck-vor-Architektur-Gate)
- **Zweck-, Scope- & Architektur-Abgleich:** Neues Pflicht-Gate in `SKILL.md` (Grundregel 1 + Phase 1), neuer Vorab-Block `0` in `references/PRUEFKATALOG.md` und Pflicht-Kopfblock `## Zweck, Scope & Ziel-Domäne` in `references/BERICHT_VORLAGE.md` sowie `--report-draft`, damit das Analyse-System zuerst Zweck, Beschreibung (`Use when` / `Don't use`) und Ziel-Domäne verifiziert, bevor es die technische Architektur bewertet.
- **Automatisierter Purpose-Alignment-Check (`SV-P3-09`):** `scripts/audit_quality.py` (`check_purpose_alignment()`) erkennt fehlende Negativ-Abgrenzungen (`Don't use`) bei breiten Beschreibungen sowie Diskrepanzen zwischen in `description` versprochenen Skripten und fehlendem `scripts/`-Ordner; als 26. stabile Regel in `scripts/audit_sarif.py` (`SV-P3-09`) integriert.
- **Neuer Eval-Fall:** `eval-11-purpose-before-architecture` in `evals/cases.json` (11 Szenarien).

## [1.4-DE] – 2026-11-18

### Hinzugefügt (P1–P4)
- **Unicode-Smuggling & Bidi-Trojan-Source (`CVE-2021-42574`):** Erkennung versteckter Zero-Width-, Tag- und bidirektionaler Steuerzeichen in Markdown, Frontmatter und Skripten (P1).
- **AST-Skript-Sicherheit & Hardcoded Secrets:** Statische Sicherheitsprüfung von Python- und Shell-Skripten (`eval`, `exec`, `shell=True`, Credential-Zugriff, `curl | sh`) sowie Suche nach fest einprogrammierten Secrets (P1).
- **Orphan-Files & Multi-Step-Workflow-Qualität:** Erkennung verwaister Dateien in `scripts/`, `references/` und `assets/` sowie Prüfkriterien für Exit-Bedingungen pro Schritt, Retry-Limit + Fallback bei Schleifen und beobachtbare Trigger (P2).
- **`agentskills.io`-Spec-Konformität:** Validierung von `name` (≤ 64 Zeichen, Kleinbuchstaben/Ziffern/Bindestriche, kein `--`) und `compatibility` (≤ 500 Zeichen) (P2/P3).
- **Contamination- & Struktur-Checks:** Warnung vor README-Tier-Sektionen in `SKILL.md` (`Installation`, `License`, `Contributing`) und Cross-Language-Contamination (P3).
- **Stabile Regel-IDs & SARIF-Export:** Eindeutige Regel-IDs (`SV-P1-01`…) und `--sarif`-Ausgabe für GitHub Code Scanning / PR-Annotationen (P4).
- **Negative-Trigger-Coverage & Leakage-Lint:** Prüfung von `evals/cases.json` auf `should_trigger: false`-Fälle und Prompt-Leakage, zwei neue Eval-Fälle (`eval-09-out-of-scope-no-trigger`, `eval-10-security-orphan-sarif`) sowie Open-Source-Referenzen in `NOTICE.md` (P4).

## [1.3-DE] – 2026-11-18

### Behoben (P1/P2)
- `scripts/skill_audit.py`: YAML-Frontmatter-Parser unterstützt nun Flow-Multiline-Scalars (ohne `>`/`|`), Inline-Listen (`[...]`) und Inline-Kommentare.
- `scripts/skill_audit.py`: Link-Regex verarbeitet Dateinamen/Anker mit runden Klammern `(...)` sowie Link-Titel korrekt.
- `scripts/skill_audit.py` & `scripts/add_toc.py`: Ungeschlossene Fenced Code Blocks werden nun auch erkannt, wenn später ein zweiter Codeblock folgt.
- `scripts/add_toc.py`: Bestehende manuelle Inhaltsverzeichnisse (ohne `<!-- TOC_START -->`) werden verlustfrei abgelöst statt verdoppelt.
- `scripts/skill_audit.py`: Trigger-Erkennung um `use after`/`use for`/`don't use` sowie echte DE+EN-Prüfung (`bilingual_de_en`) erweitert.
- Fehlalarme bei Coding-/DevOps-Skills reduziert (Zielprojekt-Manifeste wie `package.json`, `pnpm-lock.yaml` und absolute Systempfade).
- `sys.dont_write_bytecode = True` in beiden Skripten + neuer Hygiene-Check `no_bytecode_or_junk` (`__pycache__`, `.pyc`, `.DS_Store`) und Frontmatter-`file_names`-Abgleich.

### Hinzugefügt (P3/P4)
- Neue Audit-Sensoren in `scripts/skill_audit.py`: Mermaid-Syntax-Lint, Sandbox-Anti-Pattern-Scanner (`sudo`/`apt-get` in Shell-Blöcken), Hardcoded-Platform-Path-Check, Überlängen-Liste (> 1.500 Zeichen) und Bundle-Budget-Warnung (46-KB-Limit von `get_skill_resources`).
- Neuer CI-/Validator-Parameter `--fail-on {none,p1,p2,p3}` mit Exit-Code `1` bei Überschreitung.
- Erweiterte `evals/cases.json`-Validierung (eindeutige IDs, `must_contain`-Typprüfung), 25+ Selbsttests und zwei neue Eval-Fälle (`eval-07-ci-strict-mode`, `eval-08-bytecode-and-bundle-budget`).
- GitHub-Repository-Struktur (`README.md`, `LICENSE`, `NOTICE.md`, `CHANGELOG.md`, `.gitignore`, `.github/workflows/ci.yml`).

## [1.2-DE]

- Erweiterter Selbsttest (18+ Regressionstests B1–B6, F1–F4, L1–L4), Report-Draft-Ausgabe (`--report-draft`), Abschnitts-Breakdown (`--sections`), Modus-A/B-Hygiene und `evals/cases.json`.
