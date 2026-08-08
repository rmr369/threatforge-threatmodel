# Example output

Produced by scanning `tests/fixtures/vulnerable` (a deliberately bad 28-asset stack):

    threatforge scan tests/fixtures/vulnerable -o example-report

- `security-report.html` — open this in a browser. Interactive: filter by risk,
  STRIDE, namespace, confidence; click any row for evidence, risk arithmetic,
  and a paste-ready patch. Tabs for attack paths, the DFD, posture charts,
  and method/coverage notes.
- `threat-model.md` — the same content as a written threat model document.
- `threatforge.sarif` — what GitHub Code Scanning consumes.
- `dfd.mmd` — Mermaid data flow diagram, grouped by trust boundary.

For contrast, `tests/fixtures/hardened` produces **zero** critical or high findings.
