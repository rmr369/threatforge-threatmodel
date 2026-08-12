# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Workbook export, for handing threats to the people who will fix them.

Written against the OOXML spreadsheet format with `zipfile` and string
formatting rather than openpyxl. That is a deliberate trade: the whole tool
installs with one dependency, and a security tool nobody can install is a
security tool nobody runs. The subset used here -- inline strings, a handful of
fonts and fills, frozen headers and autofilters -- is small, stable, and opens
in Excel, LibreOffice and Google Sheets.

Sheets are ordered by who reads them. Summary for whoever asked for the report,
Threats for the engineer who has to act, then the supporting detail.
"""

from __future__ import annotations

import datetime as _dt
import re
import zipfile
from typing import Any, Dict, List, Optional, Sequence

from ..model import ThreatModel

STRIDE_FULL = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service",
    "E": "Elevation of privilege",
}

# style ids, in the order they are written into styles.xml
S_PLAIN, S_HEAD, S_TITLE, S_WRAP, S_CRIT, S_HIGH, S_MED, S_LOW, S_INFO, S_MONO = range(10)

_SEV_STYLE = {"critical": S_CRIT, "high": S_HIGH, "medium": S_MED,
              "low": S_LOW, "info": S_INFO}

_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(v: Any) -> str:
    text = "" if v is None else str(v)
    text = _ILLEGAL.sub("", text)
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def _col(n: int) -> str:
    """0 -> A, 26 -> AA."""
    name = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        name = chr(65 + rem) + name
    return name


class _Sheet:
    def __init__(self, name: str, widths: Sequence[int]) -> None:
        # Excel rejects these characters in a sheet name, and silently
        # truncates past 31 -- both produce a file that opens with a repair
        # prompt, which is worse than a shortened tab.
        self.name = re.sub(r"[\\/*?\[\]:]", "-", name)[:31]
        self.widths = widths
        self.rows: List[List[tuple]] = []

    def add(self, values: Sequence[Any], style: int = S_PLAIN,
            styles: Optional[Sequence[int]] = None) -> None:
        self.rows.append([(v, (styles[i] if styles and i < len(styles) else style))
                          for i, v in enumerate(values)])

    def blank(self) -> None:
        self.rows.append([])

    def xml(self, freeze: int = 1, autofilter: bool = True) -> str:
        cols = "".join(
            f'<col min="{i+1}" max="{i+1}" width="{w}" customWidth="1"/>'
            for i, w in enumerate(self.widths))
        body = []
        for r, row in enumerate(self.rows, start=1):
            if not row:
                body.append(f'<row r="{r}"/>')
                continue
            cells = []
            for c, (value, style) in enumerate(row):
                ref = f"{_col(c)}{r}"
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    cells.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
                else:
                    cells.append(
                        f'<c r="{ref}" s="{style}" t="inlineStr">'
                        f'<is><t xml:space="preserve">{_esc(value)}</t></is></c>')
            body.append(f'<row r="{r}">{"".join(cells)}</row>')
        pane = ""
        if freeze:
            pane = (f'<pane ySplit="{freeze}" topLeftCell="A{freeze+1}" '
                    f'activePane="bottomLeft" state="frozen"/>')
        filt = ""
        if autofilter and self.rows and len(self.rows) > freeze:
            last = f"{_col(len(self.widths) - 1)}{len(self.rows)}"
            filt = f'<autoFilter ref="A{freeze}:{last}"/>'
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetViews><sheetView workbookViewId="0">{pane}</sheetView></sheetViews>'
            f'<cols>{cols}</cols><sheetData>{"".join(body)}</sheetData>{filt}</worksheet>')


_STYLES = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="5">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="15"/><name val="Calibri"/></font>
<font><sz val="11"/><color rgb="FF7F1D1D"/><b/><name val="Calibri"/></font>
<font><sz val="10"/><name val="Consolas"/></font>
</fonts>
<fills count="8">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1F2937"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFECACA"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFED7AA"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFDE68A"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFBFDBFE"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFE5E7EB"/></patternFill></fill>
</fills>
<borders count="1"><border/></borders>
<cellStyleXfs count="1"><xf/></cellStyleXfs>
<cellXfs count="10">
<xf fontId="0" applyAlignment="1"><alignment vertical="top"/></xf>
<xf fontId="1" fillId="2" applyFill="1" applyFont="1" applyAlignment="1"><alignment vertical="center"/></xf>
<xf fontId="2" applyFont="1"/>
<xf fontId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf>
<xf fontId="3" fillId="3" applyFill="1" applyFont="1" applyAlignment="1"><alignment vertical="top" horizontal="center"/></xf>
<xf fontId="0" fillId="4" applyFill="1" applyAlignment="1"><alignment vertical="top" horizontal="center"/></xf>
<xf fontId="0" fillId="5" applyFill="1" applyAlignment="1"><alignment vertical="top" horizontal="center"/></xf>
<xf fontId="0" fillId="6" applyFill="1" applyAlignment="1"><alignment vertical="top" horizontal="center"/></xf>
<xf fontId="0" fillId="7" applyFill="1" applyAlignment="1"><alignment vertical="top" horizontal="center"/></xf>
<xf fontId="4" applyFont="1" applyAlignment="1"><alignment vertical="top"/></xf>
</cellXfs></styleSheet>'''


def _refs(finding, key: str) -> str:
    return ", ".join((finding.references or {}).get(key, []) or [])


def _build(model: ThreatModel, document: Optional[Dict[str, Any]] = None,
           findings=None) -> List[_Sheet]:
    doc = (document or {}).get("fields", {}) or {}
    answers = (document or {}).get("answers", {}) or {}
    rows = list(findings if findings is not None else model.active_findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda f: (order.get(f.risk_level.value, 9), -f.risk_score))
    counts = model.counts()

    # -- Summary ----------------------------------------------------------
    s = _Sheet("Summary", [34, 22, 60])
    s.add([doc.get("title") or model.project or "Threat model"], S_TITLE)
    s.blank()
    s.add(["Field", "Value", "Notes"], S_HEAD)
    s.add(["Generated", _dt.datetime.now().strftime("%Y-%m-%d %H:%M"), ""])
    s.add(["Owner", doc.get("owner", ""), "Accountable for the decisions below"])
    s.add(["Reviewer", doc.get("reviewer", ""), ""])
    s.add(["Stakeholders", doc.get("stakeholders", ""), ""])
    s.add(["Data classification", doc.get("data_classification", ""), ""])
    s.add(["Compliance drivers", doc.get("compliance", ""), ""])
    s.blank()
    s.add(["Severity", "Open threats", "What it means"], S_HEAD)
    meaning = {
        "critical": "Exploitable now, with a direct route to data or control",
        "high": "Exploitable given one further condition",
        "medium": "Real, but needs a precondition an attacker cannot assume",
        "low": "Worth fixing when the code is next touched",
        "info": "Coverage gaps and unanswered design questions, not threats",
    }
    for level in ("critical", "high", "medium", "low", "info"):
        s.add([level.title(), counts.get(level, 0), meaning[level]],
              styles=[_SEV_STYLE[level], S_PLAIN, S_WRAP])
    s.blank()
    s.add(["STRIDE category", "Threats", "Reading"], S_HEAD)
    per = {k: 0 for k in STRIDE_FULL}
    for f in rows:
        for letter in (f.stride or []):
            key = getattr(letter, "value", letter)
            if key in per:
                per[key] += 1
    for k, name in STRIDE_FULL.items():
        s.add([f"{k} · {name}", per[k],
               "No threats found in this category — check the questions were asked"
               if not per[k] else ""], styles=[S_PLAIN, S_PLAIN, S_WRAP])
    s.blank()
    s.add(["Model size", "", ""], S_HEAD)
    s.add(["Components", len(model.assets), ""])
    s.add(["Data flows", len(model.flows), ""])
    s.add(["Trust boundaries", len(model.boundaries), ""])
    s.add(["Attack paths", len(model.attack_paths),
           "A complete route from an external entity to something worth reaching"],
          styles=[S_PLAIN, S_PLAIN, S_WRAP])

    # -- Threats ----------------------------------------------------------
    t = _Sheet("Threats", [13, 10, 7, 42, 34, 46, 18, 16, 14, 40, 11, 12])
    t.add(["Rule", "Severity", "Score", "Threat", "Component", "Why it matters",
           "Weakness (CWE)", "Technique", "OWASP / NIST", "What to do",
           "Evidence", "STRIDE"], S_HEAD)
    for f in rows:
        src = f.primary_source
        where = ""
        if src and src.file:
            where = src.file + (f":{src.line}" if src.line else "")
        stride = ",".join(getattr(x, "value", x) for x in (f.stride or []))
        t.add([
            f.rule_id, f.risk_level.value, f.risk_score, f.title, f.component,
            " ".join((f.description or "").split()),
            _refs(f, "cwe"), _refs(f, "mitre"),
            " / ".join(x for x in (_refs(f, "owasp"), _refs(f, "nist")) if x),
            (f.remediation.summary if f.remediation else ""),
            where, stride,
        ], styles=[S_MONO, _SEV_STYLE.get(f.risk_level.value, S_PLAIN), S_PLAIN,
                   S_WRAP, S_MONO, S_WRAP, S_PLAIN, S_PLAIN, S_PLAIN, S_WRAP,
                   S_MONO, S_PLAIN])

    # -- Components -------------------------------------------------------
    c = _Sheet("Components", [40, 15, 13, 12, 10, 9, 26, 46])
    c.add(["Component", "Type", "Kind", "Trust zone", "Hops from internet",
           "Blast radius", "Data handled", "Answered design attributes"], S_HEAD)
    for a in sorted(model.assets.values(), key=lambda x: x.id):
        if a.element.value not in ("process", "data_store", "external_entity"):
            continue
        attrs = {k[5:]: v for k, v in a.facts.items()
                 if k.startswith("attr.") and not k.startswith("attr._")}
        zone = next((x.split(":", 1)[1] for x in sorted(a.tags)
                     if x.startswith("trust_zone:")), "")
        hops = a.facts.get("exposure_hops")
        c.add([a.id, a.element.value, a.kind, zone,
               "not reachable" if hops is None else hops,
               a.facts.get("blast_radius", 0),
               ", ".join(sorted(d.value for d in a.data_classes)),
               "; ".join(f"{k}={v}" for k, v in sorted(attrs.items()))],
              styles=[S_MONO, S_PLAIN, S_PLAIN, S_PLAIN, S_PLAIN, S_PLAIN,
                      S_PLAIN, S_WRAP])

    # -- Attack paths -----------------------------------------------------
    p = _Sheet("Attack paths", [7, 8, 34, 34, 9, 60, 34])
    p.add(["#", "Score", "Entry point", "Objective", "Hops", "Route",
           "Cut any one of these"], S_HEAD)
    for i, path in enumerate(model.attack_paths, start=1):
        # `hop_labels` is a presentation concern the API computes; here the
        # model is in hand, so the same lookup is done directly. An id with no
        # asset behind it keeps its id rather than becoming a blank cell.
        labels = [model.assets[h].display if h in model.assets else h
                  for h in path.hops]
        p.add([i, path.score, labels[0] if labels else "",
               labels[-1] if labels else "", len(path.hops),
               " → ".join(labels), ", ".join(path.findings)],
              styles=[S_PLAIN, S_PLAIN, S_PLAIN, S_PLAIN, S_PLAIN, S_WRAP, S_WRAP])

    # -- Document ---------------------------------------------------------
    d = _Sheet("Document", [30, 90])
    d.add(["Field", "Value"], S_HEAD)
    for key in ("title", "owner", "reviewer", "stakeholders", "scope",
                "out_of_scope", "assumptions", "dependencies",
                "data_classification", "compliance"):
        d.add([key.replace("_", " ").title(), doc.get(key, "")],
              styles=[S_PLAIN, S_WRAP])
    d.blank()
    d.add(["Security question", "Answer"], S_HEAD)
    from ..library import SECURITY_QUESTIONS
    for q in SECURITY_QUESTIONS:
        d.add([f"[{q['stride']}] {q['q']}", answers.get(q["id"], "") or "UNANSWERED"],
              styles=[S_WRAP, S_WRAP])

    return [s, t, c, p, d]


def render(model: ThreatModel, path: str,
           document: Optional[Dict[str, Any]] = None, findings=None) -> str:
    """Write the workbook to `path` and return it."""
    sheets = _build(model, document, findings)

    types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
             '<Default Extension="xml" ContentType="application/xml"/>'
             '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
             '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
             + "".join(
                 f'<Override PartName="/xl/worksheets/sheet{i+1}.xml" '
                 'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                 for i in range(len(sheets)))
             + '</Types>')

    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')

    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets>' + "".join(
              f'<sheet name="{_esc(s.name)}" sheetId="{i+1}" r:id="rId{i+1}"/>'
              for i, s in enumerate(sheets))
          + '</sheets></workbook>')

    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join(
                   f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/'
                   f'officeDocument/2006/relationships/worksheet" '
                   f'Target="worksheets/sheet{i+1}.xml"/>' for i in range(len(sheets)))
               + f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.'
                 'openxmlformats.org/officeDocument/2006/relationships/styles" '
                 'Target="styles.xml"/></Relationships>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", types)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        z.writestr("xl/styles.xml", _STYLES)
        for i, sheet in enumerate(sheets):
            z.writestr(f"xl/worksheets/sheet{i+1}.xml",
                       sheet.xml(freeze=1 if i else 0, autofilter=bool(i)))
    return path


def render_bytes(model: ThreatModel, document: Optional[Dict[str, Any]] = None,
                 findings=None) -> bytes:
    import io
    buf = io.BytesIO()
    sheets = _build(model, document, findings)
    import tempfile
    import os as _os
    fd, tmp = tempfile.mkstemp(suffix=".xlsx")
    _os.close(fd)
    try:
        render(model, tmp, document, findings)
        with open(tmp, "rb") as fh:
            return fh.read()
    finally:
        try:
            _os.unlink(tmp)
        except OSError:
            pass
