<div align="center">

# ThreatForge

**Automated, evidence-based threat modelling for infrastructure-as-code.**

[![tests](https://img.shields.io/badge/tests-78%20passing-brightgreen)](tests/test_pipeline.py)
[![rules](https://img.shields.io/badge/rules-77%20across%207%20packs-blue)](threatforge/rules/packs)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-lightgrey)](LICENSE)

Point it at a repository. It builds a connected architecture graph across
Kubernetes, Helm, Kustomize, Terraform, Dockerfiles and Compose; derives trust
boundaries; runs STRIDE driven by *observed configuration*; scores each threat
by how exposed and how valuable the component actually is; traces attack paths
from the internet to your crown jewels; and gates your CI.

</div>

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [What makes a finding](#what-makes-a-finding)
- [Risk scoring](#risk-scoring)
- [Attack paths](#attack-paths)
- [Command reference](#command-reference)
- [Outputs](#outputs)
- [Configuration](#configuration)
- [CI/CD integration](#cicd-integration)
- [Rule packs](#rule-packs)
- [Writing your own rules](#writing-your-own-rules)
- [Extending to new source types](#extending-to-new-source-types)
- [Python API](#python-api)
- [Migrating from the stage1–12 scripts](#migrating-from-the-stage112-scripts)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development](#development)

---

## Why this exists

The obvious way to automate STRIDE is to walk every component and emit the six
threat categories for each. It is also the wrong way. A 274-resource repository
produces ~2,300 threats, ~1,800 of them rated High, and the output is unusable:
nothing distinguishes the 1,800, and no evidence is attached to any of them.

Worse, every number in that report is determined *before the parser reads a
line of YAML*. Two identical clusters — one hardened, one not — produce
identical output.

ThreatForge inverts this. **A threat is emitted only when a fact extracted from
a real manifest satisfies a rule's predicate**, and every finding cites the
file, line, and config path that triggered it.

The two bundled fixtures make the difference measurable:

| Fixture | Assets | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|
| `tests/fixtures/vulnerable` | 28 | **17** | 22 | 21 | 12 |
| `tests/fixtures/hardened` | 11 | **0** | 0 | 0 | 1 |

A scanner that cannot go quiet on a well-configured system is a scanner nobody
keeps in their pipeline. `test_hardened_is_quiet` enforces that in CI.

---

## Install

Requires Python 3.9+. Install once — ThreatForge never needs to live inside the
projects you scan.

### Recommended: pipx (isolated, always on PATH)

```bash
pip install pipx
pipx ensurepath
pipx install /path/to/threatforge
```

### Alternative: pip

```bash
cd /path/to/threatforge
pip install -e ".[all]"
```

### Verify

```bash
threatforge --version      # threatforge 1.0.0
```

If you get `'threatforge' is not recognized`, your Python `Scripts`/`bin`
directory is not on PATH. Either use `python -m threatforge.cli` in place of
`threatforge` everywhere below, or see
[Troubleshooting](#threatforge-is-not-recognized).

### Optional extras

| Extra | Command | Enables |
|---|---|---|
| Word reports | `pip install python-docx` | `-f docx` |
| Better Terraform | `pip install python-hcl2` | Accurate HCL parsing without a plan file |
| Helm rendering | [install helm](https://helm.sh/docs/intro/install/) | Full chart expansion |
| Kustomize rendering | [install kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/) | Overlay expansion |

`.[all]` covers the two Python extras. Helm and kustomize are external binaries;
without them, charts are parsed best-effort and the report says so under
*Parse warnings*.

---

## Quick start

```bash
cd /path/to/your-infra-repo
threatforge scan .
```

Open `threatforge-out/security-report.html`.

Scan a project somewhere else, writing the report elsewhere too:

```bash
threatforge scan /path/to/other-project -o ~/reports/other-project
```

> **Windows/PowerShell:** `~` is **not** expanded by PowerShell or cmd. Use a
> full path or `$HOME`:
> ```powershell
> threatforge scan C:\Users\AD\repos\app
> threatforge scan $HOME\repos\app
> ```
> Passing a literal `~/repos/app` now fails with exit code 2 rather than
> creating a `~` directory.

Try it on the bundled fixture first if you want to see what a populated report
looks like:

```bash
threatforge scan tests/fixtures/vulnerable -o /tmp/demo -v
```

---

## How it works

```
 sources                    graph                     analysis                 output
 ─────────                  ─────                     ────────                 ──────
 k8s manifests  ┐                                                         ┌─ security-report.html
 Helm charts    │        ┌─ assets  ─┐                                    ├─ threatforge.sarif
 Kustomize      ├─ ingest┤  flows    ├─ boundaries ─ reachability ─ facts ─┤─ threat-model.md/.docx
 Terraform      │        └─ ...     ─┘       │            │          │    ├─ threat-model.json
 Dockerfiles    │                            │            │          │    ├─ dfd.mmd
 Compose        │                       trust levels  exposure    controls├─ attack-path-N.mmd
 live cluster   ┘                                     blast radius   │    └─ exit code (CI gate)
 legacy JSON                                                         │
                                                         rules ──────┘
                                                           │
                                                    risk scoring
                                                           │
                                                    attack paths
```

Nine stages, each reading only what the previous one produced, so any stage can
be replaced without touching its neighbours. `threatforge scan . -v` prints
per-stage timing and object counts.

| Stage | Module | Does |
|---|---|---|
| ingest | `ingest/` | Source files → `Asset` objects, with file:line provenance |
| relate | `graph/relationships.py` | Label selectors, ingress backends, volume/secret refs, RBAC, netpol, cross-provider links |
| boundaries | `graph/boundaries.py` | Nested trust boundaries with trust levels 0–95 |
| reachability | `graph/reachability.py` | Hops from untrusted entry points; blast radius |
| facts | `controls.py` | ~120 named facts per asset: which controls exist, which don't |
| rules | `rules/engine.py` | Declarative YAML predicates over facts |
| risk | `risk.py` | Likelihood × impact, exposure- and control-adjusted |
| suppress | `risk.py` | Config ignores + accepted-risk baseline |
| attack paths | `graph/attackpath.py` | BFS from internet to crown jewels |

### Supported sources

| Source | Rules | Depth |
|---|---:|---|
| Kubernetes YAML | 50 | Full — selectors, RBAC, volumes, NetworkPolicy, PSA |
| Helm charts | *(same 50)* | Full with `helm` on PATH; degraded otherwise |
| Kustomize overlays | *(same 50)* | Full with `kustomize` or `kubectl` |
| Live cluster | *(same 50)* | Full, via `kubectl`; secret values never read |
| Terraform (AWS/Azure/GCP) | 10 | Good with plan JSON, partial from raw HCL |
| Dockerfile | 6 | Build-time posture |
| docker-compose | 6 | Runtime topology |
| Cross-source data flows | 5 | Any combination of the above |

Honest framing: this is a Kubernetes tool with real multi-cloud and
container-build coverage attached, not an even-handed generalist. The *engine*
is provider-agnostic — see [Extending](#extending-to-new-source-types).

Not supported: CloudFormation, CDK, Pulumi, Bicep/ARM, Ansible, Serverless
Framework, Nomad, CI/CD pipeline definitions.

---

## What makes a finding

Three things, all required.

**1. A fact.** `controls.py` extracts named facts per asset —
`container.privileged`, `pod.sensitive_host_path`, `rbac.escalation_paths`,
`ing.tls`, `tf.imdsv2_required`, `net.has_ingress_policy` — each carrying a
`SourceRef`. Facts record controls that are present *and* controls that are
absent.

**2. A rule.** Declarative YAML in `threatforge/rules/packs/`:

```yaml
- id: TF-K8S-001
  title: Container runs in privileged mode
  severity: critical
  stride: [E, T, I]
  confidence: confirmed
  applies_to: {kind: [Container]}
  when:
    all:
      - {fact: container.privileged, op: is_true}
  evidence:
    - {fact: container.privileged, text: "securityContext.privileged is true", expected: false}
  description: >
    Disables essentially every container isolation control. An attacker with code
    execution here can mount the host filesystem, read kubelet credentials, and
    take over the node — and from the node, every other pod scheduled on it.
  remediation:
    summary: Remove privileged mode and grant only the capabilities needed.
    patch: |
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
    effort: medium
    breaking_risk: medium
  references:
    cwe: [CWE-250, CWE-269]
    mitre: [T1611, T1610]
    cis: ["5.2.1"]
    nist: [AC-6, CM-7]
```

There is no code path that assigns a threat to a component because of its type.

**3. Context.** The rule's severity is the starting point, not the answer — see
below.

---

## Risk scoring

`likelihood × impact`, each 1–5, giving 1–25.

| Factor | Effect |
|---|---|
| 0–1 hops from an untrusted entry point | likelihood **+1** |
| No path from any external entity | likelihood **−2** |
| Confidence is `possible` | likelihood **−1** |
| Ingress NetworkPolicy present (network rules) | likelihood **−1** |
| Seccomp profile present (escape rules) | likelihood **−1** |
| Namespace enforces restricted PSA | likelihood **−1** |
| Holds secrets or credentials | impact **+1** |
| Has a path to a sensitive data store | impact **+1** |
| Blast radius ≥ 15 / ≥ 50 assets | impact **+1** / **+2** |
| Control-plane or production namespace | impact **+1** |

Levels: ≥20 critical · ≥12 high · ≥6 medium · else low.

Every adjustment is recorded on the finding and rendered in the report:

```
Risk 20/25 — likelihood 4 × impact 5 · critical
Exposure: 2 hop(s) from the internet · blast radius 18 · sensitivity 5
  [directly_internet_exposed +1] [holds_secrets +1] [moderate_blast_radius +1]
  — Reachable from the internet in 2 hops.
  — Holds secret or credential material.
  — Compromise reaches 18 downstream assets.
```

**Severity and confidence are independent axes.** Severity is the worst
realistic outcome; confidence is how certain we are the finding is real
(`confirmed` / `likely` / `possible`). Conflating them is the most common
threat-modelling mistake.

---

## Attack paths

Findings tell you what is wrong. Attack paths tell you what an attacker would
do — which is what persuades people who don't read scanner output.

```
Attacker starts at ExternalEntity Internet.
Sends a request to Service shop/postgres, where service exposes an administrative
  or database port (TF-NET-008, risk 25) provides the next step.
Is routed to StatefulSet shop/postgres.
Pivots into Container shop/postgres/postgres, where container can escalate
  privileges (TF-K8S-002, risk 16) provides the next step.
Objective reached: Secret shop/shop-db (credential, secret).
```

Crown jewels are sensitive data stores, Secrets, privileged roles, cloud data
stores, and the node filesystem. Paths are scored by the findings along them and
by length — a two-hop path to a database beats a seven-hop one.

---

## Command reference

```bash
threatforge scan   [PATH]   # full pipeline + all reports
threatforge gate   [PATH]   # CI gate only
threatforge diff   [PATH] --against old.json
threatforge baseline [PATH] # freeze current findings as accepted risk
threatforge dfd    [PATH]   # diagram only
threatforge rules           # list loaded rules
threatforge init   [PATH]   # write a starter .threatforge.yml
threatforge migrate [PATH]  # import legacy stage7-dfd.json
```

`PATH` defaults to `.`. Global flags (`--no-color`, `--version`) come **before**
the subcommand.

### scan

```bash
threatforge scan .                          # everything, default formats
threatforge scan . -v                       # per-stage timing
threatforge scan . -o ~/reports/app         # output elsewhere
threatforge scan . -f html -f sarif         # pick formats (repeatable)
threatforge scan . --fail-on high           # scan and gate in one step
threatforge scan . --ingestor terraform     # restrict sources (repeatable)
threatforge scan . --live                   # also collect from the live cluster
threatforge scan . --quiet                  # suppress console summary
threatforge scan . -c ./ci/threatforge.yml  # explicit config
```

### gate

```bash
threatforge gate .
threatforge gate . --fail-on critical --max-new 3
threatforge gate . --json                   # machine-readable
threatforge gate . --github-summary         # append to $GITHUB_STEP_SUMMARY
```

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | Pass |
| 1 | Gate failed (or `diff` found new findings) |
| 2 | Execution or usage error — bad path, unreadable config |

---

## Outputs

Written to `threatforge-out/` unless `-o` says otherwise.

| File | Use |
|---|---|
| `security-report.html` | **Start here.** Self-contained, interactive. Filter by risk/STRIDE/namespace/confidence; click a row for evidence, risk arithmetic, and a paste-ready patch. Tabs for attack paths, DFD, posture charts, method & coverage. |
| `threatforge.sarif` | GitHub Code Scanning — inline PR annotations and the Security tab |
| `threat-model.md` | Written threat model document for review |
| `threat-model.docx` | Same, for audit / ARB / compliance evidence (`-f docx`) |
| `threat-model.json` | Full model: assets, flows, boundaries, findings, paths. The API. |
| `dfd.mmd` | Mermaid data flow diagram, grouped by trust boundary |
| `dfd-exposed.mmd` | Internet-reachable subgraph only |
| `trust-boundaries.mmd` | Boundary nesting with asset counts |
| `attack-path-1.mmd` | Highest-scoring attack chain |

`.mmd` files render natively in GitHub Markdown — paste inside a
` ```mermaid ` block.

---

## Configuration

Every key has a working default; a repo with no config produces a useful report
on the first run. `threatforge init` writes a commented starter.

```yaml
# .threatforge.yml
project: my-platform

ingestors: [kubernetes, terraform, dockerfile, compose]

rules:
  packs: []                     # empty = all built-in packs
  extra_paths: [./security/rules]
  disabled: [TF-K8S-019]        # rule ids or glob patterns
  only: []                      # if set, run only these

controls:
  allowed_registries:           # empty = TF-K8S-021 never fires
    - ghcr.io
    - 123456789012.dkr.ecr.eu-west-1.amazonaws.com

risk:
  production_namespaces: [prod, payments-prod]

suppress:
  rules: []
  components: []                # glob against asset ids
  paths:                        # glob against source files
    - "**/examples/**"
    - "**/test/**"
  below_severity: null          # info | low | medium | high

gate:
  fail_on: high                 # critical | high | medium | low | none
  max_new: 0                    # new findings allowed vs baseline
  fail_on_attack_path: true

output:
  dir: threatforge-out
  formats: [json, html, sarif, markdown, mermaid]   # add 'docx'
  max_findings_in_doc: 60

helm: {render: true}
kustomize: {render: true}
live: {enabled: false, namespace: null}
```

Config and baseline are **per project** and belong in that project's repo —
`fail_on` and the accepted-risk list are project decisions, not tool decisions.

---

## CI/CD integration

### Threshold vs ratchet

This distinction decides whether the tool survives adoption.

- **Threshold** — fail if anything at or above `fail_on` exists. Correct for a
  new repository. Brutal for an existing one.
- **Ratchet** — commit a baseline; fail only on findings *not* in it. Today's
  debt is accepted, tomorrow's is blocked.

```bash
threatforge baseline .
git add .threatforge-baseline.json .threatforge.yml
git commit -m "chore: adopt ThreatForge with current state baselined"
```

The gate then reports accepted debt separately and blocks only regressions:

```
====================================================================
  ThreatForge security gate — FAIL
====================================================================
  mode        : ratchet (baseline present)
  fail_on     : high
  findings    : 17 critical · 23 high · 21 medium · 12 low
  attack paths: 6 (0 critical)
  accepted    : 72 in baseline
  fixed       : 1 since baseline — nice

  ✗ 1 new finding(s) at or above 'high' (allowed: 0)

  Blocking findings:
    [12] TF-K8S-011     Container image uses a mutable tag
         k8s:Container:shop/postgres/postgres  app.yaml:115
====================================================================
```

Baseline entries carry `reason`, `owner`, and `expires`, so accepted risk stays
attributable rather than becoming a silent dumping ground.

### GitHub Actions

`.github/workflows/threat-model.yml` is included and: uploads SARIF (inline PR
annotations + Security tab), publishes the HTML report as an artifact, writes a
job summary, and posts a sticky PR comment.

```yaml
permissions:
  contents: read
  security-events: write     # required for SARIF upload
  pull-requests: write       # required for the PR comment
```

Also included: `.gitlab-ci.yml` and `.pre-commit-hooks.yaml`.

### Pre-commit

```yaml
repos:
  - repo: https://github.com/YOUR-ORG/threatforge
    rev: v1.0.0
    hooks:
      - id: threatforge
```

---

## Rule packs

| Pack | Rules | Covers |
|---|---:|---|
| `k8s-workload` | 23 | Privilege, capabilities, host namespaces, host paths, images, resource limits, secrets in env, seccomp, probes |
| `k8s-identity` | 7 | ClusterRole wildcards, Secret access, escalation verbs, anonymous bindings, SA tokens |
| `k8s-network` | 12 | NetworkPolicy coverage, TLS, ingress auth and rate limiting, LoadBalancer/NodePort exposure, exposed data ports, Pod Security Admission |
| `k8s-data` | 8 | Committed secrets, credentials in ConfigMaps, secret blast radius, PV reclaim and host paths, quotas |
| `cloud-terraform` | 10 | Public buckets and databases, open security groups, encryption at rest, IAM wildcards, IMDSv1, hardcoded credentials, access logging |
| `docker-build` | 12 | Root images, mutable base tags, build secrets, `ADD` from URL, `curl \| sh`, Compose privilege/socket/ports |
| `dataflow` | 5 | Unencrypted flows from untrusted networks, sensitive data crossing boundaries, direct internet-to-datastore edges |

Every rule maps to **CWE**, **MITRE ATT&CK**, **CIS Kubernetes Benchmark**,
**NIST 800-53**, and where applicable the **OWASP Kubernetes Top 10**.

```bash
threatforge rules              # human-readable
threatforge rules --json       # machine-readable
threatforge rules --pack k8s-network
```

---

## Writing your own rules

No Python required. Drop a YAML file in `threatforge/rules/packs/`, or keep your
own directory and point `rules.extra_paths` at it.

```yaml
pack: my-org
rules:
  - id: ORG-001
    title: Workload deployed outside an approved namespace
    severity: medium
    stride: [E]
    confidence: likely
    applies_to: {kind: [Deployment, StatefulSet]}
    when:
      all:
        - {fact: namespace, op: not_in, value: [prod, staging, platform]}
    evidence:
      - {fact: namespace, text: "deployed to '{{ namespace }}'", expected: "an approved namespace"}
    description: Why an attacker cares.
    remediation: {summary: Move to an approved namespace., effort: low}
```

Predicates support `all` / `any` / `none` / `not` and operators `is_true`
`is_false` `exists` `absent` `eq` `ne` `gt` `gte` `lt` `lte` `in` `not_in`
`contains` `not_contains` `any_in` `none_in` `non_empty` `empty` `len_gt`
`len_lt` `regex` `not_regex` `glob`.

Full fact catalogue and authoring guidance:
**[docs/WRITING-RULES.md](docs/WRITING-RULES.md)**.

To see the facts available on a specific asset:

```python
from threatforge import scan
m = scan(".")
a = m.assets["k8s:Container:shop/storefront/web"]
for k, v in sorted(a.facts.items()):
    if not k.startswith("_"):
        print(f"{k:40} {v}")
```

---

## Extending to new source types

Everything after ingestion — relationships, boundaries, reachability, rules,
risk, attack paths, all six output formats — operates on `Asset` / `Flow` /
`Boundary` and never on Kubernetes types. That is why a Terraform RDS instance
and a Kubernetes StatefulSet both appear as data stores in the same DFD.

Adding a provider is two things, no core changes:

```python
from threatforge.ingest.base import Ingestor, register
from threatforge.model import Asset, Element

@register
class CloudFormationIngestor(Ingestor):
    name = "cloudformation"
    provider = "cloudformation"

    def detect(self, root: str) -> bool:
        ...        # cheap check: is there anything here for me?

    def ingest(self, root: str, model) -> None:
        ...        # emit Assets only; relationships come later
        self.emit(model, Asset(id="cfn:...", kind="AWS::S3::Bucket",
                               name="assets", provider="cloudformation",
                               element=Element.DATA_STORE, spec=raw))
```

Then a rule pack in YAML. `ingest/terraform.py` is a ~250-line reference.

---

## Python API

```python
from threatforge import scan

model = scan("./infra")

print(model.counts())
# {'critical': 17, 'high': 22, 'medium': 21, 'low': 12, 'info': 0}

for f in model.active_findings[:10]:
    src = f.primary_source
    print(f"{f.risk_score:>2} {f.rule_id} {f.component} {src.file}:{src.line}")

for path in model.attack_paths[:3]:
    print(path.score, " → ".join(path.hops))

# Coverage across workloads
print(model.metadata["control_coverage"])
```

Useful objects: `ThreatModel`, `Asset`, `Flow`, `Boundary`, `Finding`,
`Evidence`, `Remediation`, `RiskFactors`, `AttackPath`, and the enums
`Severity`, `Confidence`, `DataClass`, `Element`.

---

## Migrating from the stage1–12 scripts

```bash
threatforge migrate /path/containing/stage7-dfd.json
```

Imports `architecture.json` and/or `stage7-dfd.json`, normalises the old
`Kind:namespace:name` ids to the canonical `k8s:Kind:namespace/name` URN scheme
so both files merge into one graph, then rebuilds boundaries, reachability, and
findings.

Legacy JSON discarded the `spec`, so control-based rules cannot fire against
it — `controls.py` detects this and skips fact extraction rather than inventing
facts from missing data. Re-scan the original manifests for the full picture.

Stage-by-stage mapping: **[docs/MIGRATION.md](docs/MIGRATION.md)**.

---

## Troubleshooting

### `'threatforge' is not recognized`

Your Python scripts directory isn't on PATH. Either use the module form —

```bash
python -m threatforge.cli scan .
```

— or add the directory printed by:

```bash
python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
```

On Windows: *Settings → System → About → Advanced system settings →
Environment Variables → Path → New*, then open a **new** terminal.

### `error: scan target does not exist`

The path is wrong. On PowerShell and cmd this is almost always `~`, which those
shells do not expand:

```powershell
threatforge scan ~/repos/app       # ✗ literal '~/repos/app'
threatforge scan $HOME\repos\app   # ✓
threatforge scan C:\Users\AD\repos\app   # ✓
```

### `warning: no infrastructure was found`

The scan ran but recognised nothing. Check you're pointing at the right
directory, that files use `.yaml` / `.yml` / `.tf` / `Dockerfile` naming, and
that `suppress.paths` isn't excluding them. `-v` shows per-ingestor file counts.

### Helm charts produce few or no assets

Install `helm`. Without it, `{{ }}` blocks are blanked out and values-dependent
structure is lost. Check *Parse warnings* in the report.

### Terraform findings are all `possible`

Raw HCL can't resolve variables, locals, or module defaults. Generate a plan:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
threatforge scan .          # plan.json is picked up automatically
```

### Monorepo cross-references break

Scanning a subdirectory means references outside it can't resolve — you'll get
`TF-DATA-004 undeclared reference` instead of real edges. Scan the common
ancestor and use `suppress.paths` to filter noise, rather than narrowing the
scan root.

### Too many findings on first run

Expected on an established repo. Baseline it, then ratchet down:

```bash
threatforge baseline .
```

---

## Limitations

Read this before quoting the output at anyone.

- **Static analysis only.** No application code, no image contents, no CVEs, no
  runtime behaviour. Pair with an image scanner and a runtime sensor.
- **Manifests can lie.** Admission controllers, mutating webhooks, mesh
  sidecars, and operators change what actually runs. Findings marked `likely`
  acknowledge this.
- **Helm without `helm`** loses values-dependent structure.
- **Terraform without a plan** can't resolve variables or module defaults.
- **Cross-provider links are heuristic.** A pod → RDS edge inferred from an env
  var hostname is labelled `possible` and drawn as a dashed line.
- **Absence of a finding is not evidence of absence of risk.** The coverage
  panel exists so you can see what was and wasn't examined.

---

## Development

```bash
make install     # pip install -e ".[all,dev]"
make test        # 78 tests
make demo        # scan the vulnerable fixture
make gate
```

The suite covers signal-to-noise on both fixtures, every high-value detection,
graph resolution (selectors, ingress backends, secret references, RBAC
bindings), reachability, risk explainability, the gate in both modes, SARIF
validity, HTML self-containment, CLI argument handling, and robustness against
malformed YAML and Helm templates.

```
threatforge/
├── model.py            canonical objects — Asset, Flow, Boundary, Finding
├── pipeline.py         stage orchestration
├── controls.py         fact extraction (the evidence layer)
├── risk.py             scoring + suppression
├── gate.py             CI gate, threshold and ratchet
├── config.py           .threatforge.yml + baseline
├── cli.py              command line
├── ingest/             kubernetes · terraform · docker · legacy
├── graph/              relationships · boundaries · reachability · attackpath
├── rules/
│   ├── engine.py       declarative predicate evaluation
│   └── packs/*.yaml    77 rules
└── render/             html · sarif · markdown · docx · mermaid
```

Contributions welcome — new rule packs and new ingestors are the two highest-
value additions, and neither requires touching the core.

Licence: Apache-2.0.
