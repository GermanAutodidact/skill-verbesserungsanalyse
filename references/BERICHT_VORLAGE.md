# Verbesserungsanalyse: <Skill-/Repo-Name> (v<Version>)

**Fazit:** <Gesamturteil in 1–2 Sätzen>. Gefunden: **<n> bestätigte P1-Fehler/Bugs**, **<m> Link-/Format-/Tool-Befunde (P2)** und <größtes Struktur-/Effizienzpotenzial>.

## Bestandsaufnahme (Größe ≈ Tokens)

| Datei | Zeichen | ≈ Tokens | Zeilen | TOC |
|---|---:|---:|---:|:---:|
| `SKILL.md` | <…> | <…> | <…> | ✅/❌ |
| `references/<…>.md` | <…> | <…> | <…> | ✅/❌ |

> [!NOTE]
> <Kurzbewertung des Kontext-Budgets: z. B. „Gesamtgröße optimal, kein Split nötig“ ODER Warnung bei > 60k Tokens / Doppelpflege.>

---

## 🔴 Priorität 1: Fachliche Fehler & Bugs (verifiziert)

| # | Fundstelle | Problem | Korrektur |
|---|---|---|---|
| F1 | [`<datei>#L<z>`](file:///…) | <Problem> | <konkrete Korrektur> |

## 🟠 Priorität 2: Ausführbarkeit, Links & Formatierung
- **Defekte Links / Codeblöcke / Mermaid / Format-Lint:** <Befund mit Fundstelle>
- **Tote lokale Tool-/Datei-Verweise & Hygiene (`__pycache__` / `file_names`):** `<liste>`
  - **Option A (empfohlen):** <echtes Hilfsskript mit `--self-test` mitliefern>
  - **Option B:** <auf „falls verfügbar“ umformulieren + Fallback ergänzen>

## 🟡 Priorität 3: Struktur, Effizienz & Plattform-Tauglichkeit
1. <Nur vorschlagen, was zur Größe passt — kein Over-Engineering bei kleinen Skills!>
2. <Zweisprachige Description (DE+EN), portabler Pfad, Bundle-Budget (> 46 KB), Modus A/B, Sicherheitsklausel>

## 🔵 Priorität 4: Qualitätssicherung & Hygiene

| Maßnahme | Nutzen |
|---|---|
| `evals/cases.json` | <…> |
| Selbsttests / Validator (`--fail-on p2`) + CI *(bei Git-Repos)* | <…> |
| `LICENSE` + `NOTICE.md` + `CHANGELOG.md` *(bei Git-Repos mit externen Quellen)* | <…> |

---

## Empfohlene Umsetzungsreihenfolge

```mermaid
flowchart LR
  A["P1: Fehler & Bugs"] --> B["P2: Tools, Links & Format"]
  B --> C["P3: Effizienz, Struktur & Cross-Platform"]
  C --> D["P4: Evals, Tests, Hygiene & Version"]
```

Aufwand: <kurze realistische Einschätzung>.
