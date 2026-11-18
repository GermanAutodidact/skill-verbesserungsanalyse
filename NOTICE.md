# NOTICE

`skill-verbesserungsanalyse` ist eine Eigenentwicklung unter der [MIT License](LICENSE).

- **Standardbibliothek only:** Die Python-Skripte (`scripts/skill_audit.py`, `scripts/add_toc.py`) nutzen ausschließlich die Python-Standardbibliothek (Python 3.10+) ohne Drittanbieter-Abhängigkeiten.
- **Konventionen:** Die Markdown-Anker-Bildung orientiert sich an den CommonMark- (§4.5 Fenced Code Blocks) und GitHub-Flavored-Markdown-Spezifikationen.

## Inspirationen & Referenzen (Open Source)

Die Prüfregeln, Spezifikations-Checks und Bewertungskriterien in `skill-verbesserungsanalyse` sind konzeptionell inspiriert von folgenden Open-Source-Projekten (ohne Übernahme von Fremdcode):

- [`agentskills/agentskills`](https://github.com/agentskills/agentskills) (`skills-ref`, Apache-2.0) — Spezifikation für Skill-Frontmatter (`name`, `compatibility`) und Validierungsreferenz.
- [`NVIDIA/SkillEvaluator`](https://github.com/NVIDIA/SkillEvaluator) (Apache-2.0) — Qualitätsdimensionen für Workflow-Schritte, Sicherheitsprüfungen und Skill-Evaluation.
- [`agent-ecosystem/skill-validator`](https://github.com/agent-ecosystem/skill-validator) (MIT) — Struktur-, Contamination- und Link-/Referenz-Prüfungen für Agent-Skills.
- [`William-Yeh/agent-skill-linter`](https://github.com/William-Yeh/agent-skill-linter) (Apache-2.0) — Linting-Regeln, Regel-IDs und maschinenlesbare CI-Ausgaben.
- [`adewale/skill-eval-harness`](https://github.com/adewale/skill-eval-harness) (MIT) — Eval-Design inkl. Negative-Trigger-Tests und Prompt-Leakage-Vermeidung.
- [`coolapso/agent-skills-validator`](https://github.com/coolapso/agent-skills-validator) (MIT) — Sicherheits-, Spec- und Hygiene-Validierung für Agent-Skill-Repositories.
