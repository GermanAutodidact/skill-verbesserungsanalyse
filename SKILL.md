---
name: skill-verbesserungsanalyse
description: Strukturierte Verbesserungsanalyse (Audit) für KI-Skills, Wissensdatenbanken und Doku-Repos – automatische Bestandsaufnahme (Token-Budget, Abschnittsgrößen, Links/Anker, tote Verweise, Format-Lint), fachliche Prüfung, priorisierter Bericht (P1–P4) und verifizierte Umsetzung nach Freigabe. Use when the user asks to review, audit, improve or "verbessern/überprüfen/optimieren" a skill, SKILL.md, prompt, knowledge base or docs repo ("Ist das noch verbesserbar?", "Skill überprüfen", "Verbesserungsanalyse", "improvement review"). Don't use for general application code reviews unrelated to skills/prompts/docs.
metadata:
    version: 1.6-DE
---
# Skill-Verbesserungsanalyse (Audit → Bericht → Umsetzung)

Systematisches Vorgehen für eine **belegbare Verbesserungsanalyse** von KI-Skills, Prompts, Wissensdatenbanken oder Doku-Repos. Ergebnis ist ein **priorisierter Bericht (P1–P4)** als Markdown-Artefakt; umgesetzt wird erst nach Nutzer-Freigabe.

> [!IMPORTANT]
> **Grundregeln:**
> 1. **Erst Zweck, Anspruch-vs.-Wirklichkeit & Widersprüche klären (inkl. Rückfrage-Pflicht), dann Architektur bewerten** — `name`, `description` (`Use when` / `Don't use`), Ziel-Domäne und Zielplattform direkt aus `SKILL.md` belegen, **Anspruch vs. Wirklichkeit (Claim-vs.-Reality)** gegen tatsächlich vorhandene Skripte, Referenzen, Flags und Workflows abgleichen und auf innere **Widersprüche** prüfen (`Don't use for X` im Frontmatter vs. Workflow für `X` im Body). **Rückfrage-Pflicht (Clarification Gate):** Bleiben Zweck, Ziel-Domäne oder Scope-Grenzen nach dem Lesen von `SKILL.md` mehrdeutig oder widersprüchlich, **vor** der technischen Architektur-Bewertung innehalten und beim Nutzer klären.
> 2. **Erst messen, dann urteilen** — jeder Befund braucht einen Beleg (`Datei:Zeile`, grep-Treffer, Regel-ID oder Messwert) sowie eine transparente Diagnose-Sicherheit (`[Verifiziert]` vs. `[Heuristik / Verdacht]`).
> 3. **Jeden Verdacht vorab verifizieren** (`grep`/`view_file`), inklusive Kopien/Gesamtausgaben.
> 4. **Nichts ändern vor Freigabe** des Berichts; Inhalte stets **verlustfrei** erhalten und Datei-Änderungen, Git-Commit und Git-Push als getrennte Freigabe-Schritte behandeln.
> 5. **Größen-Proportionalität (kein Over-Engineering):** Kleine Skills (< 15k Tokens, 1–3 Dateien) brauchen keinen Split, keinen Handbuch-Generator und kein künstliches TOC.

---

## Priorisierungs-Matrix

| Stufe | Kriterium | Beispiele |
|---|---|---|
| **🔴 P1** | Sachlich falsch, gefährlich oder kaputter Code/Befehl | Physikalische/fachliche Fehler, Bugs in Skripten, kaputte CLI-Flags, `sudo`/`apt-get` in Sandbox-Skills, Unicode-Tag-Smuggling / Bidi-Overrides (`CVE-2021-42574`), AST-/Skript-Risiken (`eval`/`exec`/`shell=True`/Credential-Zugriff/`curl \| sh`), Hardcoded Secrets |
| **🟠 P2** | Blockiert KI-Ausführung oder beschädigt Lesbarkeit/Links | Tote lokale Tool-/Datei-Verweise, verwaiste Dateien (Orphan-Files in `scripts/`/`references/`/`assets/`), fehlender Prozess-Lifecycle-/Orphan-Schutz in Skripten & Sidecars (`SV-P2-12`), defekte Links/`#Anker`, ungeschlossene Codeblöcke, Mermaid-Syntaxfehler, Format-Lint, `agentskills.io`-Spec-Fehler, Zero-Width-Zeichen, unbegründete `audit-ok`-Unterdrückungen (Pflichtformat `# audit-ok: <Begründung>`), `__pycache__`/`.pyc`-Junk |
| **🟡 P3** | Effizienz, Kontext-Budget & Plattform-Tauglichkeit | Purpose-vs.-Architektur-Drift & Claim-vs.-Reality-Abweichungen (`SV-P3-09`: fehlende `Don't use`-Abgrenzung, versprochene Skripte/Flags fehlen, Frontmatter/Body-Widerspruch), Versions- & Regel-Inkonsistenz (`SV-P3-10`: Drift zwischen Code-SSOT, Doku & Evals), große ungeteilte Dateien (> 40k Tokens), Dopplungen, fehlende DE/EN-Trigger, hardcoded Pfade, Bundle > 46 KB, Cross-Language-Contamination, README-Tier-Sektionen oder fehlende Verifikation in Multi-Step-Workflows, fehlende Negative-Trigger-Evals / Prompt-Leakage, fehlende Ethik-Schranke |
| **🔵 P4** | Nachhaltige Qualitätssicherung & Hygiene | `evals/cases.json` inkl. Negative-Trigger & Adversarial-Fällen, ausgebaute Selbsttests, CI-Validator (`--fail-on`, `--sarif`), `LICENSE`/`NOTICE.md`/`CHANGELOG.md` |

---

## Phase 1 – Zweck, Ziel-Modus & automatische Bestandsaufnahme

1. **Zweck, Anspruch-vs.-Wirklichkeit & Modus zuerst verifizieren (Pflicht-Gate vor Architektur-Kritik):**
   - `SKILL.md`-Frontmatter (`name`, `description`, `Use when` / `Don't use`) und den Einstieg lesen und in 2–3 Sätzen festhalten: *Wofür ist der Skill gedacht? Was schließt er explizit aus? Welcher Skill-Typ liegt vor (Fach-/Wissens-, Coding-/DevOps- oder Workflow-/Prompt-Skill)?*
   - **Anspruch vs. Wirklichkeit (Claim-vs.-Reality) & Widersprüche prüfen:** Enthält das Bundle tatsächlich die in `description` versprochenen Skripte, Referenzen, CLI-Flags und Workflows? Gibt es Widersprüche zwischen Frontmatter und Body (z. B. `Don't use for X` im Frontmatter vs. Anleitung für `X` im Haupttext)?
   - **Rückfrage-Pflicht (Clarification Gate):** Sind Zweck, Ziel-Domäne oder Scope-Grenzen nach der Lektüre von `SKILL.md` unklar, mehrdeutig oder selbstwidersprüchlich, **pausieren und den Nutzer gezielt um Klärung bitten**, bevor Architektur-Noten oder Umbau-Empfehlungen vergeben werden.
   - **Modus A (Skill-Ordner ohne Git):** z. B. `~/.gemini/skills/<name>/` oder `~/.claude/skills/<name>/`.
   - **Modus B (Git-Repository + ggf. installierter Skill):** Repo-Checkout **und** installierte Skill-Kopie notieren (beide bleiben synchron).
2. **Audit-Skript direkt im Terminal ausführen** (`<skill-dir>/scripts/skill_audit.py`; je nach Plattform unter `~/.gemini/skills/skill-verbesserungsanalyse/scripts/` oder `~/.claude/skills/…` — Skripte **nicht** zusammen mit Referenzen über `get_skill_resources` laden, um das 46-KB-Limit nicht zu reißen; per `get_skill_resources` nur `references/PRUEFKATALOG.md` und `references/BERICHT_VORLAGE.md` holen):
   ```bash
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner>                  # Voll-Report (inkl. Auto-Sections >10k tok)
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --sections       # Abschnittsgrößen aller Dateien
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --report-draft   # Vorbefüllter Entwurf nach BERICHT_VORLAGE.md
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --fail-on p2     # CI-/Validator-Modus (Exit 1 ab P2)
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --sarif          # SARIF 2.1.0 für GitHub Code Scanning
   python3 <skill-dir>/scripts/skill_audit.py <ziel-ordner> --json           # Maschinenlesbar inkl. Regel-IDs
   python3 <skill-dir>/scripts/skill_audit.py --rules                        # Alle 28 stabilen Regel-IDs (SV-P1-01…SV-P3-10)
   ```
   Prüft automatisch (über `skill_audit.py` + Hilfsmodule `audit_security.py`, `audit_quality.py`, `audit_sarif.py`): Zweck-/Scope-Erfassung, Claim-vs.-Reality- & Widerspruchs-Abgleich (`SV-P3-09`), Versions- & Regel-Konsistenz zwischen Code-SSOT, Doku & Evals (`SV-P3-10`), Inventar (Zeichen/≈Tokens/TOC/LaTeX/Bundle-Bytes), Abschnitts-Breakdown großer Dateien, Frontmatter & `agentskills.io`-Spec (NFKC-`name`, `compatibility`, `file_names`-Abgleich, ≤ 1024 Zeichen, DE+EN-Trigger), echte Markdown-Links (inkl. `%20`, Klammern, Link-Titel & GitHub-Slugs), ungeschlossene Codeblöcke, Mermaid-Lint, tote lokale Verweise **und** transitive Orphan-Files (BFS ab `SKILL.md`), Format-Lint, Portabilität/Sandbox-Anti-Patterns, **Unicode-Smuggling & Bidi-Overrides**, **erweiterten Security- & Secret-Scan** über `.py`, `.sh`/`.bash`, `.js`/`.ts`, `.ps1`, `.env`, `.toml`, `.yaml`, `.json`, `.md` inkl. **Scan-Coverage** (`scanned_files` vs. `skipped_files`) und Begründungspflicht für Ausnahmen (`# audit-ok: <Begründung>` / `// audit-ok: <Begründung>`; bloßes `# audit-ok` ohne Begründung wird als P2 gemeldet), **Prozess-Lifecycle-/Orphan-Prüfung (`SV-P2-12`)**, Cross-Language-Contamination, README-Tier- & Workflow-Heuristiken, Datei-Duplikate, `evals/cases.json`-Schema + Negative-Trigger-/Leakage-Lint, Sicherheits-Heuristik, **28 stabile Regel-IDs (`SV-P1-01`…`SV-P3-10` inkl. `SV-P2-12`)**, SARIF-2.1.0-Export und Modus-A/B-Hygiene inkl. `__pycache__`/`.pyc`-Check.
3. **Gezielt gegenlesen:** Passt die implementierte Architektur (Skripte, Referenzen, Workflows) wirklich zum erfassten Zweck? Vorhandene Skripte per `--self-test` prüfen.

## Phase 2 – Fachliche & qualitative Tiefenprüfung + Bericht

1. **Tiefenprüfung nach Prüfkatalog:** Die Checkliste in `references/PRUEFKATALOG.md` (Vorab-Gate `0` + Kategorien A–G) domänenpassend abarbeiten (Fach-/Wissens-, Coding-/DevOps- oder Prompt-/Workflow-Skill). Jeden Verdacht vor Aufnahme in den Bericht per `grep -n` / `view_file` bestätigen, alle betroffenen Kopien notieren und Befunde sauber in **`[Verifiziert]`** (deterministisch geprüft/reproduziert) vs. **`[Heuristik / Verdacht]`** (manuell zu bestätigen) trennen.
2. **Bericht schreiben & Freigabe einholen:** Bericht als Artefakt `<artefakt-dir>/<Name>_Verbesserungsanalyse.md` (`UserFacing: true`, `RequestFeedback: true`; auf anderen Plattformen als Markdown-Datei oder Chat-Bericht) anhand von `references/BERICHT_VORLAGE.md` (oder `--report-draft` als Basis) mit Fundstelle (`Datei:Zeile`), Nachweis/Snippet, Diagnose-Sicherheit, Korrekturvorschlag und Regressionstest anlegen. Im Chat danach **nicht** den Bericht wiederholen — nur die 3–4 wichtigsten Funde knapp nennen und um Freigabe für die gewünschten Pakete (oder alle) bitten.

## Phase 3 – Kontrollierte Umsetzung & Verifikation (nur nach Freigabe)

1. **Gezielte Umsetzung in Reihenfolge P1 → P4:**
   - **Vor und nach den Edits `git status --short` prüfen** (in Modus B), damit keine fremden oder unbeabsichtigten Arbeitsbaum-Änderungen übersehen werden.
   - **P1/P2 (Fehler, Sicherheit, Lifecycle, Links, Tools):** Gezielt editieren (z. B. `replace_file_content` / Edit-Tool); Sicherheits-/Unicode-/AST-Befunde bereinigen (Ausnahmen nur mit `# audit-ok: <Begründung>` bzw. `// audit-ok: <Begründung>`); bei **`SV-P2-12`-Befunden** fehlenden Schutz gegen verwaiste/doppelte Prozesse automatisch direkt im Code nachrüsten (`atexit`/`signal`-Cleanup, Parent-PID-Watchdog für STDIO-/Child-Prozesse, `daemon_threads = True` für Threading-Server, PID-/Single-Instance-Guard sowie Timeout-geschütztes `.terminate()`/`.wait(timeout)`); bei toten Tool-Verweisen entweder ein echtes Skript mit `--self-test` liefern oder auf *„falls verfügbar“* + Fallback umformulieren; verwaiste Dateien (Orphan-Files) verlinken oder entfernen.
   - **P3 (Struktur & Cross-Platform, proportional zur Größe):** Große Dateien verlustfrei an Überschriftsgrenzen splitten; Inhaltsverzeichnisse & Anker idempotent mit `<skill-dir>/scripts/add_toc.py <datei1> …` erzeugen (`--check` für CI); doppelt gepflegte Gesamtausgaben über ein deterministisches Generator-Skript (`--check`) ersetzen; zweisprachige `description` (DE/EN, ≤ 1024 Zeichen), `agentskills.io`-konformer `name`, portable Skript-Pfade, passende Sicherheitsklausel sowie konsistente Version & Regel-Zählung (`SV-P3-10`).
   - **P4 (QS & Hygiene):** `evals/cases.json` inkl. Negative-Trigger & Adversarial-Checks anlegen/erweitern, Skript-Selbsttests ausbauen; in **Modus B** zusätzlich Validator (`skill_audit.py --fail-on p2`, optional `--sarif`), `LICENSE`/`NOTICE.md`/`CHANGELOG.md` pflegen.
2. **Verifikation & Sync:**
   - **Beide Modi:** Eventuelle `__pycache__/`-Ordner bzw. `.pyc`-Dateien entfernen (`PYTHONDONTWRITEBYTECODE=1` oder `sys.dont_write_bytecode = True` in Skripten nutzen), alle Skript-Selbsttests (`--self-test`), ggf. `add_toc.py --check` / `validate*.py` sowie ein **Re-Audit** mit `skill_audit.py --fail-on p2` ausführen — erst bei 0 Regressionen fortfahren.
   - **Modus A (Skill-Ordner):** Per `update_skill` aktualisieren (Antigravity-Registry; auf anderen Plattformen genügt direktes Speichern im Skill-Ordner); schlägt `update_skill` auf Shared-FS wegen `chmod` auf Unterordnern fehl, Ressourcen kurz nach `/tmp` sichern → `delete_skill` → `save_skill(content=…)` → Ressourcen per Python `read_bytes`/`write_bytes` zurückkopieren → per `lookup_skill` verifizieren.
   - **Modus B (Git-Repo — Staged-Approval-Workflow):**
     1. Nach den Datei-Änderungen `git status --short` prüfen und dem Nutzer `git diff --stat` (auf Wunsch den vollständigen Diff) zeigen bzw. zusammenfassen.
     2. **Exakt nur die explizit geänderten Dateien stagen** (`git add <datei1> <datei2>` — **niemals** blindes `git add -A`, wenn unbeteiligte untracked/modified Dateien im Arbeitsbaum liegen).
     3. **Datei-Änderungen → Git-Commit → Git-Push als getrennte Freigabe-Checkpoints behandeln** (sofern der Nutzer nicht explizit Commit + Push in einem Durchgang angefordert hat). Änderungen in die installierte Skill-Kopie synchronisieren (Python `read_bytes`/`write_bytes` statt `cp` auf Shared-FS, ohne `__pycache__`) und nach erfolgtem Push CI mit `gh run watch <id> --exit-status` prüfen.
3. **Abschlussmeldung:** Knapp auf Deutsch mit klickbaren Dateilinks, Testergebnissen, `git diff --stat`-Zusammenfassung sowie (in Modus B nach Freigabe) Commit-Hash und CI-Status.