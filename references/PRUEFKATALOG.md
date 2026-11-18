# Prüfkatalog für die Verbesserungsanalyse (v1.4.1-DE)

Jeden Punkt mit **Beleg** (Datei:Zeile, grep-Treffer oder Messwert) bewerten: ✅ ok | ⚠️ verbesserbar | ❌ Fehler.

## 0. Zweck-, Scope- & Architektur-Abgleich (Pflicht-Gate vor P1–P4)
- [ ] **Zweck & Ziel-Domäne korrekt erfasst:** `name`, `description` (Trigger + `Don't use`-Abgrenzung), Skill-Typ (Fach-/Wissens-, Coding-/DevOps- oder Workflow-/Prompt-Skill) und Zielplattform aus `SKILL.md` belegt, **bevor** Architektur-Empfehlungen formuliert werden.
- [ ] **Purpose-vs.-Architektur-Konsistenz:** Deckt sich die `description` mit den tatsächlich umgesetzten Workflows, Referenzen und `scripts/` (kein *Scope-Drift* — weder ungedeckte Versprechen noch ungetriggerte Kernfunktionen)?
- [ ] **Passung geplanter Empfehlungen:** Widerspricht keine geplante Maßnahme (z. B. Split, CI, Ethik-Schranke, Skript-Ergänzung) dem erklärten Zweck oder der expliziten `Don't use`-Grenze des Skills?

## A. Fachliche Korrektheit, Sicherheit & technische Ausführbarkeit (→ P1)
- [ ] **Plausibilität & Korrektheit nach Skill-Typ:**
  - *Fach-/Wissens-Skill:* physikalische Grenzwerte, Einheiten, Formeln, Originalquellen-Treue (z. B. Trockeneis nicht unter −78,5 °C; Regeln nicht enger/weiter als im Original).
  - *Coding-/DevOps-Skill:* veraltete CLI-Flags/APIs, fehlerhafte Befehle, unsichere Defaults, falsche Umgebungsannahmen (z. B. `sudo`/`apt` in Sandbox ohne Root — automatisch geprüft in Shell-Blöcken).
  - *Prompt-/Workflow-Skill:* widersprüchliche Regeln (z. B. „extrem ausführlich“ vs. „maximal 3 Sätze“), fehlende Abbruch-/Verifikationskriterien.
- [ ] **Unicode-Smuggling & Bidi-Trojan-Source (`CVE-2021-42574`):** Keine versteckten Zero-Width-, Tag- oder bidirektionalen Steuerzeichen in Markdown, Frontmatter oder Skripten.
- [ ] **AST-Skript-Sicherheit & Hardcoded Secrets:** Python-/Shell-Skripte frei von unsicheren Konstrukten (`eval`, `exec`, `subprocess(..., shell=True)`, unerwartetem Credential-Zugriff, `curl | sh`) sowie fest einprogrammierten API-Keys, Tokens oder Passwörtern.
- [ ] **Innere Widersprüche:** derselbe Sachverhalt an zwei Stellen unterschiedlich definiert oder benannt.
- [ ] **Kopien & Spiegel:** Steht ein Fehler auch in Gesamtausgaben oder in einer zweiten Kopie (Repo vs. installierter Skill)? Alle Fundstellen auflisten.

## B. Ausführbarkeit & Agentic-Skill-Qualität (→ P2)
- [ ] Existiert zu jedem erwähnten Tool, Skript oder Pfad eine Datei im Zielordner oder ein verfügbares Paket? (Stimmen auch Frontmatter-`file_names`?)
- [ ] **Keine verwaisten Dateien (Orphan-Files):** Jede Datei in `scripts/`, `references/` und `assets/` wird aus `SKILL.md` oder einer eingebundenen Referenz aktiv verlinkt/genutzt.
- [ ] Sind optionale Tools als „falls verfügbar“ gekennzeichnet und gibt es einen Fallback ohne Tools?
- [ ] Laufen mitgelieferte Skripte (`--help`, `--self-test`) fehlerfrei?
- [ ] Sind **Trigger-Bedingungen** klar definiert (*wann anwenden* **und** *wann nicht anwenden*)?
- [ ] **Multi-Step-Workflow-Qualität:** Klare Exit-/Verifikationsbedingungen pro Schritt, explizites Retry-Limit + Fallback bei Schleifen sowie beobachtbare Trigger statt vager Formulierungen (z. B. „falls sinnvoll“).

## C. Formatierung, Links & Integrität (→ P2)
- [ ] Keine defekten relativen Markdown-Links `[Text](pfad.md#anker)` oder `#Anker` (automatisch per `skill_audit.py`).
- [ ] Keine ungeschlossenen Fenced Code Blocks (```` ``` ````), kein kaputtes Markdown, keine fehlenden Leerzeichen oder Trailing Whitespace.
- [ ] **Mermaid-Diagramme:** nur unterstützte Diagrammtypen (`flowchart`, `sequenceDiagram`, `stateDiagram-v2`, `classDiagram`, `erDiagram`, `xychart-beta`) und Knotenlabels mit Klammern in Anführungszeichen (`id["Label (Info)"]`).
- [ ] Extrem lange Zeilen (> 1.500 Zeichen) erschweren Diffs und Reviews; LaTeX-Dichte nur dort, wo Zielplattformen rendern.

## D. Struktur & Kontext-Budget (→ P3) — *proportional zur Größe!*
- [ ] **Anti-Over-Engineering:** Kleine Skills (< 15k Tokens, 1–3 Dateien) brauchen **keinen** Split, **keinen** Generator und kein künstliches TOC.
- [ ] `SKILL.md` kompakt halten (~1,5–15k Tokens); Detailtabellen in `references/` auslagern (Progressive Disclosure).
- [ ] **Keine README-Tier-Sektionen & keine Cross-Language-Contamination:** `SKILL.md` enthält keine Repo-Metadaten wie `Installation`, `License` oder `Contributing` (gehören ins `README.md`) und mischt keine fremden Ökosysteme/Sprachen ohne Anlass.
- [ ] **Bundle-Budget (Modus A):** Überschreitet das Gesamt-Bundle 46 KB (`get_skill_resources`-Limit), klar dokumentieren, dass Skripte direkt im Terminal laufen statt mit den Referenzen in den Kontext geladen zu werden.
- [ ] Große Referenzdateien (> 15k Tokens): Inhaltsverzeichnis mit Ankern/Zeilenbereichen (`scripts/add_toc.py`) und bei > 40k Tokens Warnung *„nicht komplett laden“*.
- [ ] Routing-Tabelle in `SKILL.md`: Welche Anfrage führt zu welcher Datei/welchem Abschnitt?
- [ ] **Single Source of Truth:** Werden Inhalte in einer Gesamtausgabe doppelt gepflegt, per Generator-Skript (`--check`) statt manuell pflegen.
- [ ] Große Rohdaten-Blöcke (Register, SMIRKS, JSON-Dumps) auslagern (`references/02b_…` oder `data/`).

## E. Plattform-übergreifende Nutzung (→ P3)
- [ ] **`agentskills.io`-Spec-Konformität:** `name` ≤ 64 Zeichen, nur Kleinbuchstaben, Ziffern und einzelne Bindestriche (kein `--`, nicht am Anfang/Ende), `compatibility` ≤ 500 Zeichen.
- [ ] `description` zweisprachig (DE/EN) mit klaren „Use when …“-Triggern, ≤ 1.024 Zeichen.
- [ ] Portabler Skript-Aufruf (kein fest verdrahteter Pfad auf genau eine Plattform wie `~/.gemini/…`, wenn der Skill auch in Claude Code / Codex laufen soll).
- [ ] Bei Wissens-Skills für Web-Chats: Kompakt-Prompt unter dem Zeichenlimit (< 5.000 Zeichen) + Upload-Hinweise im README.

## F. Sicherheit & Recht (→ P3/P4)
- [ ] Bei sicherheitsrelevanten Domänen (Chemie, Bio, Security, Finanzen, Medizin): explizite Ethik-/Dual-Use-Schranke und Schutzhinweise.
- [ ] Bei Git-Repos mit externen Quellen: `LICENSE` (NC/SA vererbt sich!) und `NOTICE.md` mit allen Quellen und Lizenzen.

## G. Qualitätssicherung & Hygiene (→ P4)
- [ ] Keine Bytecode-/Junk-Dateien (`__pycache__/`, `*.pyc`, `.DS_Store`) im Skill-Ordner; in Python-Skripten `sys.dont_write_bytecode = True` setzen.
- [ ] `evals/cases.json` mit aussagekräftigen Testfällen (eindeutige `id`, `prompt`, `expected_modules`, `must_contain`, `must_not_contain`), inkl. Regressionsfällen, **Negative-Trigger-Coverage** (`should_trigger: false`) und **Leakage-Lint** (keine `must_contain`-Antwortbegriffe wörtlich im `prompt`).
- [ ] Bei Repos mit Validator/CI: stabile Regel-IDs (`SV-P1-01`…) und `--sarif`-Ausgabe für GitHub Code Scanning neben Frontmatter-, Größen-, Link-, Regressions-Lint (`skill_audit.py --fail-on p2`), Generator-Sync- und Skript-Selbsttests.
- [ ] `CHANGELOG.md` (bei Repos) und Versionssprung im Frontmatter.
