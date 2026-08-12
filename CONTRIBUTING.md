# Contributing

Two additions carry the most value and neither requires touching the core:
**new rule packs** and **new ingestors**.

## Licence and sign-off

ThreatForge is [MPL-2.0](LICENSE). Two consequences for contributors:

1. **New source files need the MPL header.** Three comment lines at the top —
   copy them from any existing file. CI does not enforce this yet; reviewers do.
2. **Every commit needs a DCO sign-off.** This is a statement that you wrote the
   code, or have the right to submit it. Read [DCO](DCO) for the exact terms.

```bash
git commit -s -m "feat: add CloudFormation ingestor"
```

`-s` appends `Signed-off-by: Your Name <you@example.com>` using your git
identity. To do it automatically from now on:

```bash
git config --global format.signOff true
```

Forgot? `git commit --amend -s --no-edit` fixes the last one, and
`git rebase --signoff origin/main` fixes a whole branch. The DCO workflow tells
you which commits are missing it.

## Setup

```bash
git clone https://github.com/rmr369/threatforge-threatmodel
cd threatforge
pip install -e ".[all,dev]"
pytest -q
```

## Adding a rule

1. Add it to an existing pack in `threatforge/rules/packs/`, or create a new
   `.yaml` file there. See [docs/WRITING-RULES.md](docs/WRITING-RULES.md).
2. Add a triggering case to `tests/fixtures/vulnerable/`.
3. Add **both** assertions:

```python
def test_my_rule_fires(vuln):
    assert any(f.rule_id == "TF-XXX-001" for f in vuln.findings)

def test_my_rule_silent_on_hardened(hard):
    assert not [f for f in hard.findings if f.rule_id == "TF-XXX-001"]
```

The second assertion is not optional. A rule never proven to stay silent is a
rule that will produce false positives in someone's repository.

`test_rules_are_well_formed` enforces that every non-info rule has a title,
description, predicate, evidence spec, STRIDE mapping, and remediation summary.

### Rule quality bar

- **Description** says what an *attacker gains*, not what the setting is.
- **Severity** is the worst realistic outcome with no compensating controls.
  Don't pre-discount for "probably internal" — `risk.py` does that with graph data.
- **Confidence** is a separate axis: `confirmed` (manifest is unambiguous),
  `likely` (runtime override conceivable), `possible` (heuristic).
- **Remediation** includes a paste-ready patch where one exists, plus honest
  `effort` and `breaking_risk`.
- **References** to CWE and MITRE ATT&CK at minimum.

## Adding an ingestor

Subclass `Ingestor`, implement `detect()` and `ingest()`, decorate `@register`.
Ingestors create Assets only — relationships, facts, rules, and risk are
downstream, so a new provider inherits the whole pipeline.
`threatforge/ingest/terraform.py` is a ~250-line reference.

Attach a `SourceRef` with file and line to everything. A finding without
provenance is an opinion.

## Before opening a PR

```bash
pytest -q                                    # all tests
threatforge scan tests/fixtures/hardened     # must stay quiet
threatforge rules                            # no load errors
```

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please don't open a public issue for a security
report.
