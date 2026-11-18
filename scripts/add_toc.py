#!/usr/bin/env python3
"""Idempotenter TOC- & Anker-Generator für große Markdown-Module (skill-verbesserungsanalyse v1.3-DE).

Fügt vor jedem ##/###-Abschnitt einen eindeutigen Anker `<a id="sec-N"></a>` sowie eine
Inhaltsverzeichnis-Tabelle mit exakten Zeilenbereichen zwischen `<!-- TOC_START -->` und
`<!-- TOC_END -->` ein. Fenced Code Blocks (``` / ~~~) werden dabei vollständig geschützt;
bereits vorhandene manuelle Inhaltsverzeichnisse (ohne Marker) werden verlustfrei abgelöst.

Nutzung:
  python3 add_toc.py datei1.md [datei2.md ...]          # Schreibt TOC & Anker idempotent
  python3 add_toc.py datei1.md --check                  # Prüft Aktualität (Exit 1 bei Abweichung)
  python3 add_toc.py --self-test                        # Selbsttest
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

sys.dont_write_bytecode = True

MANUAL_TOC_HEADING_RE = re.compile(
    r"^##\s+(Inhaltsverzeichnis|Table of Contents|Gesamt-Inhaltsverzeichnis)\b",
    re.I,
)


def _fence_mask(lines: list[str]) -> list[bool]:
    """Liefert pro Zeile True, wenn sie Teil eines Fenced Code Blocks ist (CommonMark §4.5)."""
    mask: list[bool] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in lines:
        m = re.match(r"^\s*(`{3,}|~{3,})", line)
        if m:
            marker = m.group(1)
            rest = line[m.end() :]
            is_inline_backtick = marker[0] == "`" and "`" in rest
            if not in_fence:
                # CommonMark §4.5: Backtick-Fences duerfen kein '`' im Info-String enthalten
                if is_inline_backtick:
                    mask.append(False)
                    continue
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                mask.append(True)
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                if line.strip() == marker:
                    in_fence = False
                    mask.append(True)
                    continue
                # Neuer Fence mit Info-String (z. B. ```python) nach ungeschlossenem Vor-Fence
                if rest.strip() != "" and not is_inline_backtick:
                    fence_len = len(marker)
                    mask.append(True)
                    continue
        mask.append(in_fence)
    return mask


def _is_manual_toc_span(lines: list[str], in_code: list[bool], start_idx: int) -> int | None:
    """Erkennt ein manuelles TOC ab start_idx und gibt den End-Index (exklusiv) zurück, sonst None."""
    anchor_link_lines = 0
    end_idx = start_idx + 1
    while end_idx < len(lines):
        if in_code[end_idx]:
            return None
        stripped = lines[end_idx].strip()
        if re.match(r"^#{1,3}\s+", lines[end_idx]):
            break
        if stripped == "---":
            end_idx += 1
            break
        if "](#" in stripped:
            anchor_link_lines += 1
        elif stripped and not (
            stripped.startswith("|")
            or stripped.startswith(("-", "*", "•"))
            or re.match(r"^\d+\.\s+", stripped)
            or re.match(r'^<a id="sec-\d+"></a>$', stripped)
        ):
            # Enthält reguläre Prosa -> kein reines TOC, nicht automatisch löschen
            return None
        end_idx += 1

    if anchor_link_lines < 2:
        return None
    while end_idx < len(lines) and lines[end_idx].strip() == "":
        end_idx += 1
    return end_idx


def _strip_existing_toc_and_anchors(raw_text: str) -> str:
    """Entfernt alte TOC-Blöcke (mit/ohne Marker) und sec-N-Anker ausschließlich außerhalb von Codeblöcken."""
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.splitlines(True)
    in_code = _fence_mask(lines)
    out: list[str] = []
    in_toc = False
    skip_post_toc_blanks = False
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        is_code = in_code[idx]
        if is_code:
            if not in_toc:
                out.append(line)
            idx += 1
            continue
        if not in_toc and re.match(r"^\s*<!--\s*TOC_START\s*-->\s*$", line):
            in_toc = True
            idx += 1
            continue
        if in_toc:
            if re.match(r"^\s*<!--\s*TOC_END\s*-->\s*$", line):
                in_toc = False
                skip_post_toc_blanks = True
            idx += 1
            continue
        if skip_post_toc_blanks:
            if line.strip() == "":
                idx += 1
                continue
            skip_post_toc_blanks = False
        if re.match(r'^<a id="sec-\d+"></a>\s*$', line):
            idx += 1
            continue
        if MANUAL_TOC_HEADING_RE.match(line):
            manual_end = _is_manual_toc_span(lines, in_code, idx)
            if manual_end is not None:
                idx = manual_end
                continue
        out.append(line)
        idx += 1
    return "".join(out)


def _frontmatter_end_index(lines: list[str]) -> int:
    """Liefert den ersten Zeilenindex nach einem YAML-Frontmatter-Block (oder 0)."""
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                return i + 1
    return 0


def _heading_indices_outside_code(lines: list[str]) -> set[int]:
    in_code = _fence_mask(lines)
    fm_end = _frontmatter_end_index(lines)
    return {
        i
        for i, (line, is_code) in enumerate(zip(lines, in_code))
        if i >= fm_end and not is_code and re.match(r"^#{2,3}\s+", line)
    }


def _format_toc_title(raw_title: str) -> str:
    """Bereinigt Markdown-Links und escapet eckige Klammern sowie Pipes für gültige TOC-Links."""
    cleaned = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", raw_title.strip())
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = cleaned.replace("|", "\\|").replace("[", "\\[").replace("]", "\\]")
    return cleaned


def render_with_toc(raw_text: str) -> str:
    text = _strip_existing_toc_and_anchors(raw_text)

    lines = text.splitlines(True)
    h_indices = _heading_indices_outside_code(lines)
    if not h_indices:
        return raw_text

    first_h = min(h_indices)
    anchored: list[str] = list(lines[:first_h])
    sec_num = 0
    for idx in range(first_h, len(lines)):
        if idx in h_indices:
            sec_num += 1
            anchored.append(f'<a id="sec-{sec_num}"></a>\n')
        anchored.append(lines[idx])

    def build_toc(offset: int) -> str:
        toc_lines = [
            "<!-- TOC_START -->\n",
            "## Inhaltsverzeichnis & Zeilen-Index\n\n",
            "| Abschnitt | Ebene | Zeilen |\n",
            "| :--- | :--- | :---: |\n",
        ]
        entries: list[tuple[int, str, str, int]] = []
        for idx in range(first_h, len(anchored)):
            prev = anchored[idx - 1] if idx > 0 else ""
            am = re.match(r'^<a id="(sec-\d+)"></a>\s*$', prev)
            if am:
                hm = re.match(r"^(#{2,3})\s+(.*)$", anchored[idx])
                if hm:
                    level = len(hm.group(1))
                    title = _format_toc_title(hm.group(2))
                    entries.append((level, title, am.group(1), idx + 1 + offset))
        total_lines = len(anchored) + offset
        for pos, (level, title, aid, start_ln) in enumerate(entries):
            end_ln = (entries[pos + 1][3] - 2) if pos + 1 < len(entries) else total_lines
            prefix = "" if level == 2 else "↳ "
            kind = "Hauptabschnitt" if level == 2 else "Unterabschnitt"
            toc_lines.append(f"| {prefix}[{title}](#{aid}) | {kind} | Z. {start_ln}–{end_ln} |\n")
        toc_lines.append("\n---\n\n<!-- TOC_END -->\n\n")
        return "".join(toc_lines)

    toc_offset = len(build_toc(0).splitlines())
    toc = build_toc(toc_offset)

    return "".join(anchored[:first_h]) + toc + "".join(anchored[first_h:])


def run_self_test() -> int:
    sample = (
        "---\nname: demo\n## yaml-kommentar\n---\n"
        "# Titel\n\nEinleitung.\n"
        "```inline code am Zeilenanfang```\n\n"
        "## Erstes Kapitel\nText 1.\n"
        "```markdown\n"
        "<!-- TOC_START -->\n"
        "## Fake-Ueberschrift im Code\n"
        "<!-- TOC_END -->\n"
        '<a id="sec-99"></a>\n'
        "```\n"
        "### Siehe [Guide](guide.md) [Wichtig]\nText 2.\n"
    )
    out1 = render_with_toc(sample)
    out2 = render_with_toc(out1)
    assert out1 == out2, "add_toc.py ist nicht idempotent!"
    assert "## yaml-kommentar" in out1 and '<a id="sec-1"></a>\n## yaml-kommentar' not in out1, (
        "YAML-Frontmatter wurde faelschlich verankert!"
    )
    # F1: Codeblock-Beispiel (TOC_START & sec-99) muss erhalten bleiben!
    code_part = out1.split("```markdown\n", 1)[1].split("```\n", 1)[0]
    assert "<!-- TOC_START -->" in code_part, "F1 Regression: TOC-Beispiel im Codeblock geloescht!"
    assert '<a id="sec-99"></a>' in code_part, "F1 Regression: Anker im Codeblock geloescht!"
    # F3: Inline-Triple-Backtick darf nicht als ungeschlossener Fence die echten Headings schlucken!
    assert "[Erstes Kapitel](#sec-1)" in out1, "F3 Regression: Erstes Kapitel nicht erkannt!"
    # L4: Markdown-Link + eckige Klammern sauber normalisiert/escaped
    assert "[Siehe Guide \\[Wichtig\\]](#sec-2)" in out1, f"L4 Regression: {out1}"
    # Zeilen-Index verifizieren
    out_lines = out1.splitlines()
    for m in re.finditer(r"\[((?:\\.|[^\]])+)\]\(#(sec-\d+)\)\s*\|\s*[^|]+\|\s*Z\.\s*(\d+)–(\d+)", out1):
        _, aid, start_s, _ = m.groups()
        actual_anchor = out_lines[int(start_s) - 2]
        assert actual_anchor == f'<a id="{aid}"></a>', f"Zeilenindex falsch fuer {aid} in Z.{start_s}: {actual_anchor}"

    # F4 (v1.3): Bestehendes manuelles TOC ohne Marker wird abgeloest statt verdoppelt
    manual_toc_doc = (
        "# Handbuch\n\n"
        "## Inhaltsverzeichnis\n\n"
        "- [Kapitel A](#kapitel-a)\n"
        "- [Kapitel B](#kapitel-b)\n\n"
        "---\n\n"
        "## Kapitel A\nInhalt A.\n\n"
        "## Kapitel B\nInhalt B.\n"
    )
    m_out1 = render_with_toc(manual_toc_doc)
    m_out2 = render_with_toc(m_out1)
    assert m_out1 == m_out2, "F4 Regression: Manuelles TOC nicht idempotent abgeloest!"
    assert m_out1.count("Inhaltsverzeichnis") == 1, f"F4 Regression: Doppeltes TOC erzeugt!\n{m_out1}"
    assert "[Kapitel A](#sec-1)" in m_out1 and "[Kapitel B](#sec-2)" in m_out1, (
        f"F4 Regression: Kapitel nach manuellem TOC fehlen!\n{m_out1}"
    )

    # Schutz: Ein Abschnitt namens 'Inhaltsverzeichnis' mit Prosa darf NICHT geloescht werden
    prose_toc_doc = (
        "# Guide\n\n"
        "## Inhaltsverzeichnis\n\n"
        "Dieser Abschnitt erklaert, wie man ein Inhaltsverzeichnis pflegt.\n\n"
        "## Kapitel 2\nText.\n"
    )
    p_out = render_with_toc(prose_toc_doc)
    assert "Dieser Abschnitt erklaert" in p_out, "Prosa-Abschnitt faelschlich als TOC geloescht!"

    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "doc.md"
        p.write_text(sample, encoding="utf-8")
        p.write_text(render_with_toc(p.read_text(encoding="utf-8")), encoding="utf-8")
        assert render_with_toc(p.read_text(encoding="utf-8")) == p.read_text(encoding="utf-8")

    print("OK: add_toc.py Selbsttest (Idempotenz, F1/F3/F4/L4, Codeblock-Schutz & Zeilen-Index) bestanden.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Idempotenter TOC- & Anker-Generator (v1.3)")
    parser.add_argument("files", nargs="*", help="Markdown-Dateien")
    parser.add_argument("--check", action="store_true", help="Prueft Synchronitaet ohne Schreiben")
    parser.add_argument("--self-test", action="store_true", help="Selbsttest ausfuehren")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.files:
        parser.print_help()
        return 0

    exit_code = 0
    for f in args.files:
        p = pathlib.Path(f)
        if not p.is_file():
            print(f"FEHLER: Datei nicht gefunden: {p}", file=sys.stderr)
            exit_code = 1
            continue
        current = p.read_text(encoding="utf-8")
        rendered = render_with_toc(current)
        if args.check:
            if current != rendered:
                print(f"FEHLER: TOC/Zeilen-Index in {p} nicht aktuell.", file=sys.stderr)
                exit_code = 1
            else:
                print(f"OK: {p} TOC aktuell.")
        else:
            p.write_text(rendered, encoding="utf-8")
            print(f"OK: {p} aktualisiert ({len(rendered.splitlines())} Zeilen).")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
