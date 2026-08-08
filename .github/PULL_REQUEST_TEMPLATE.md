## What changed

<!-- One or two sentences. -->

## Type

- [ ] New rule / rule pack
- [ ] New ingestor
- [ ] Bug fix
- [ ] Engine or scoring change
- [ ] Docs

## Checklist

- [ ] `pytest -q` passes
- [ ] New rules assert **both** that they fire on `tests/fixtures/vulnerable`
      and stay silent on `tests/fixtures/hardened`
- [ ] `threatforge scan tests/fixtures/hardened` still reports 0 critical / 0 high
- [ ] New facts documented in `docs/WRITING-RULES.md`
- [ ] Scoring changes explain themselves via `RiskFactors.notes`
