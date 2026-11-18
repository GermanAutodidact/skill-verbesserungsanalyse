# Changelog

Alle nennenswerten Änderungen an `skill-verbesserungsanalyse` werden hier dokumentiert.

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
