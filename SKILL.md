---
name: skill-verbesserungsanalyse
description: Strukturierte Verbesserungsanalyse (Audit) für KI-Skills, Wissensdatenbanken und Doku-Repos – automatische Bestandsaufnahme (Token-Budget, Abschnittsgrößen, Links/Anker, tote Verweise, Format-Lint), fachliche Prüfung, priorisierter Bericht (P1–P4) und verifizierte Umsetzung nach Freigabe. Use when the user asks to review, audit, improve or "verbessern/überprüfen/optimieren" a skill, SKILL.md, prompt, knowledge base or docs repo ("Ist das noch verbesserbar?", "Skill überprüfen", "Verbesserungsanalyse", "improvement review"). Don't use for general application code reviews unrelated to skills/prompts/docs.
metadata:
    version: 1.4-DE
---
# Skill-Verbesserungsanalyse (Audit → Bericht → Umsetzung)

Systematisches Vorgehen für eine **belegbare Verbesserungsanalyse** von KI-Skills, Prompts, Wissensdatenbanken oder Doku-Repos. Ergebnis ist ein **priorisierter Bericht (P1–P4)** als Markdown-Artefakt; umgesetzt wird erst nach Nutzer-Freigabe.

> [!IMPORTANT]
> **Grundregeln:**
> 1. **Erst messen, dann urteilen** — jeder Befund braucht einen Beleg (Datei:Zeile, grep-Treffer, Regel-ID oder Messwert).
> 2. **Jeden Verdacht vorab verifizieren** (`grep`/`view_file`), inklusive Kopien/Gesamtausgaben.
> 3. **Nichts ändern vor Freigabe** des Berichts; Inhalte stets **verlustfrei** erhalten.
> 4. **Größen-Proportionalität (kein Over-Engineering):** Kleine Skills (< 15k Tokens, 1–3 Dateien) brauchen keinen Split, keinen Handbuch-Generator und kein künstliches TOC.

---

## Priorisierungs-Matrix

| Stufe | Kriterium | Beispiele |
|---|---|---|
| **🔴 P1** | Sachlich falsch, gefährlich oder kaputter Code/Befehl | Physikalische/fachliche Fehler, Bugs in Skripten, kaputte CLI-Flags, `sudo`/`apt-get` in Sandbox-Skills, Unicode-Tag-Smuggling / Bidi-Overrides (`CVE-2021-42574`), AST-Skript-Risiken (`eval`/`exec`/`shell=True`/Credential-Zugriff/`curl \| sh`), Hardcoded Secrets |
| **🟠 P2** | Blockiert KI-Ausführung oder beschädigt Lesbarkeit/Links | Tote lokale Tool-/Datei-Verweise, verwaiste Dateien (Orphan-Files in `scripts/`/`references/`/`assets/`), defekte Links/`#Anker`, ungeschlossene Codeblöcke, Mermaid-Syntaxfehler, Format-Lint, `agentskills.io`-Spec-Fehler, Zero-Width-Zeichen, `__pycache__`/`.pyc`-Junk |
| **🟡 P3** | Effizienz, Kontext-Budget & Plattform-Tauglichkeit | Große ungeteilte Dateien (> 40k Tokens), Dopplungen, fehlende DE/EN-Trigger, hardcoded Pfade, Bundle > 46 KB, Cross-Language-Contamination, README-Tier-Sektionen oder fehlende Verifikation in Multi-Step-Workflows, fehlende Negative-Trigger-Evals / Prompt-Leakage, fehlende Ethik-Schranke |
| **🔵 P4** | Nachhaltige Qualitätssicherung & Hygiene | `evals/cases.json` inkl. Negative-Trigger, ausgebaute Selbsttests, CI-Validator (`--fail-on`, `--sarif`), `LICENSE`/`NOTICE.md`/`CHANGELOG.md` |

---

## Phase 1 – Ziel-Modus & automatische Bestandsaufnahme

1. **Ziel und Modus klären:**
   - **Modus A (Skill-Ordner ohne Git):** z. B. `~/.gemini/skills/<name>/` oder `~/.claude/skills/<name>/`.
   - **Modus B (Git-Repository + ggf. installierter Skill):** Repo-Checkout **und** installierte Skill-Kopie notieren (beide bleiben synchron).
2. **Audit-Skript direkt im Terminal ausführen** (`<skill-dir>/scripts/skill_audit.py`; je nach Plattform unter `~/.gemini/skills/skill-verbesserungsanalyse/scripts/` oder `~/.claude/skills/…` — Skripte **nicht** zusammen mit Referenzen über `get_skill_resources` laden, um das 46-KB-Limit nicht zu reißen; per `get_skill_resources` nur `references/PRUEFKATALOG.md` und `references/BERICHT_VORLAGE.md` holen):
   ```bash
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner>                  # Voll-Report (inkl. Auto-Sections >10k tok)
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --sections       # Abschnittsgrößen aller Dateien
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --report-draft   # Vorbefüllter Entwurf für Phase 3
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --fail-on p2     # CI-/Validator-Modus (Exit 1 ab P2)
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --sarif          # SARIF 2.1.0 für GitHub Code Scanning
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --json           # Maschinenlesbar inkl. Regel-IDs
   python3 <skill-dir>/scripts/skill_audit.py --rules                        # Alle 25 stabilen Regel-IDs (SV-P1-01…)
   ```
   Prüft automatisch (über `skill_audit.py` + Hilfsmodule `audit_security.py`, `audit_quality.py`, `audit_sarif.py`): Inventar (Zeichen/≈Tokens/TOC/LaTeX/Bundle-Bytes), Abschnitts-Breakdown großer Dateien, Frontmatter & `agentskills.io`-Spec (NFKC-`name`, `compatibility`, `file_names`-Abgleich, ≤ 1024 Zeichen, DE+EN-Trigger), echte Markdown-Links (inkl. `%20`, Klammern, Link-Titel & GitHub-Slugs), ungeschlossene Codeblöcke, Mermaid-Lint, tote lokale Verweise **und** transitive Orphan-Files (BFS ab `SKILL.md`), Format-Lint, Portabilität/Sandbox-Anti-Patterns, **Unicode-Smuggling & Bidi-Overrides**, **AST-Skript-Security & Secret-Scan**, Cross-Language-Contamination, README-Tier- & Workflow-Heuristiken, Datei-Duplikate, `evals/cases.json`-Schema + Negative-Trigger-/Leakage-Lint, Sicherheits-Heuristik, stabile Regel-IDs (`SV-P1-01`…), SARIF-2.1.0-Export und Modus-A/B-Hygiene inkl. `__pycache__`/`.pyc`-Check.
3. **Gezielt gegenlesen:** Anfang von `SKILL.md` (Frontmatter + Routing), vorhandene Skripte (`--self-test` laufen lassen!) und CI/Validator.

## Phase 2 – Fachliche & qualitative Tiefenprüfung

Die Checkliste in `references/PRUEFKATALOG.md` (Kategorien A–G) domänenpassend abarbeiten (Fach-/Wissens-, Coding-/DevOps- oder Prompt-/Workflow-Skill). Jeden Verdacht vor Aufnahme in den Bericht per `grep -n` / `view_file` bestätigen und alle betroffenen Kopien notieren.

## Phase 3 – Bericht schreiben & Freigabe einholen

Bericht als Artefakt `<artefakt-dir>/<Name>_Verbesserungsanalyse.md` (`UserFacing: true`, `RequestFeedback: true`; auf anderen Plattformen als Markdown-Datei oder Chat-Bericht) anhand von `references/BERICHT_VORLAGE.md` (oder `--report-draft` als Basis) anlegen.

Im Chat danach **nicht** den Bericht wiederholen — nur die 3–4 wichtigsten Funde knapp nennen und um Freigabe für die gewünschten Pakete (oder alle) bitten.

## Phase 4 – Verifizierte Umsetzung (nur nach Freigabe)

In Reihenfolge **P1 → P4** umsetzen:

- **P1/P2 (Fehler, Sicherheit, Links, Tools):** Gezielt editieren (z. B. `replace_file_content` / Edit-Tool); Sicherheits-/Unicode-/AST-Befunde bereinigen; bei toten Tool-Verweisen entweder ein echtes Skript mit `--self-test` liefern oder auf *„falls verfügbar“* + Fallback umformulieren; verwaiste Dateien (Orphan-Files) verlinken oder entfernen.
- **P3 (Struktur, nur wenn zur Größe passend):** Große Dateien verlustfrei an Überschriftsgrenzen splitten; Inhaltsverzeichnisse & Anker idempotent mit `<skill-dir>/scripts/add_toc.py <datei1> …` erzeugen (löst auch bestehende manuelle TOCs ab, unterstützt `--check` für CI); doppelt gepflegte Gesamtausgaben über ein deterministisches Generator-Skript (`--check`) ersetzen.
- **P3 (Cross-Platform):** Zweisprachige `description` (DE/EN, ≤ 1024 Zeichen), `agentskills.io`-konformer `name`, portable Skript-Pfade, passende Sicherheitsklausel, Version anheben.
- **P4 (QS & Hygiene):** `evals/cases.json` inkl. Negative-Trigger anlegen/erweitern, Skript-Selbsttests ausbauen; in **Modus B** zusätzlich Validator (`skill_audit.py --fail-on p2`, optional `--sarif`), `LICENSE`/`NOTICE.md`/`CHANGELOG.md` pflegen.

## Phase 5 – Verifikation, Sync & Abschluss

- **Beide Modi:** Eventuelle `__pycache__/`-Ordner bzw. `.pyc`-Dateien entfernen (`PYTHONDONTWRITEBYTECODE=1` oder `sys.dont_write_bytecode = True` in Skripten nutzen), alle Skript-Selbsttests (`--self-test`), ggf. `add_toc.py --check` / `validate*.py` sowie ein **Re-Audit** mit `skill_audit.py --fail-on p2` ausführen — erst bei 0 Regressionen abschließen.
- **Modus A (Skill-Ordner):** Per `update_skill` aktualisieren (Antigravity-Registry; auf anderen Plattformen genügt direktes Speichern im Skill-Ordner); schlägt `update_skill` auf Shared-FS wegen `chmod` auf Unterordnern fehl, Ressourcen kurz nach `/tmp` sichern → `delete_skill` → `save_skill(content=…)` → Ressourcen per Python `read_bytes`/`write_bytes` zurückkopieren → per `lookup_skill` verifizieren.
- **Modus B (Git-Repo):** Änderungen in die installierte Skill-Kopie synchronisieren (Python `read_bytes`/`write_bytes` statt `cp` auf Shared-FS, ohne `__pycache__`) und dort ebenfalls validieren; danach `git add -A && git commit -m "<version>: …" && git push` und CI mit `gh run watch <id> --exit-status` prüfen.
- **Abschlussmeldung:** Knapp auf Deutsch mit klickbaren Dateilinks, Testergebnissen sowie (in Modus B) Commit-Hash und CI-Status.