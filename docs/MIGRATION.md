# Migrating from the stage1–12 scripts

Your original pipeline and this framework do the same job. The difference is
that the stages are now composable functions over a shared object model instead
of scripts that pass JSON files to each other by filename.

## Stage mapping

| Old stage | Old script | Now |
|---|---|---|
| 1 YAML discovery | `yaml-parser.py` `find_yaml_files()` | `ingest/base.py` `walk_files()` — with exclusion of `.git`, `vendor`, `node_modules`, and Chart/values files |
| 2 PyYAML parsing | `yaml-parser.py` `parse_yaml_file()` | `ingest/base.py` `load_yaml_with_lines()` — multi-doc, duplicate-key tolerant, Helm-template tolerant, **and it records line numbers** |
| 3 Normalised JSON | `architecture.json` | `model.Asset` objects held in memory; `threat-model.json` is an output artefact, not the interface |
| 4 Relationship discovery | `generate-dfd.py` name matching | `graph/relationships.py` — label selectors with `matchExpressions`, ingress backends (v1 and v1beta1), Gateway API, PVC/PV/StorageClass chains, `secretKeyRef`/`envFrom`/projected volumes, ServiceAccount and RBAC bindings, NetworkPolicy `podSelector`, cross-provider IRSA and endpoint inference |
| 5 DFD JSON | `dfd.json` | `ThreatModel.assets` + `.flows` |
| 6 Mermaid | `generate-mermaid.py`, `simple-dfd.py` | `render/mermaid.py` — trust-boundary subgraphs, DFD-correct shapes, risk colouring, node-count capping, namespace and reachability scoping |
| 7 Accurate k8s relationships | `stage7_relationships.py` | folded into stage 4 above |
| 8 Threat-model elements | `stage8_threat_model.py` | `graph/boundaries.py` (nested boundaries with trust levels) + `Element` classification during ingest, with data-store reclassification for database workloads |
| 9 STRIDE | `stage9_stride.py` | `rules/` — **this is the substantive change**, see below |
| 10 Risk scoring | `stage10_risk_engine.py` | `risk.py` — exposure- and control-adjusted, with an explanation attached to every score |
| 11 Remediation | (planned) | part of each rule: summary, guidance, paste-ready patch, effort, breaking risk |
| 12 Report/dashboard | (planned) | `render/html.py`, `render/sarif.py`, `render/markdown.py`, `render/docx_report.py`, plus `gate.py` |

## The stage 9 change

Your stage 9 looped over every process, data store, flow, and external entity
and emitted a fixed set of STRIDE letters for each. That is a correct
*enumeration* of the STRIDE method and an incorrect *application* of it: STRIDE
is a prompt for a human to look for a specific weakness, not a claim that the
weakness exists.

The arithmetic:

```
254 processes × 6 letters   = 1,524
 29 data stores × 3 letters =    87
181 data flows × 4 letters  =   724
  1 external entity × 2     =     2
                              ─────
                              2,337 threats
```

Every number in that output was determined before the parser read a single
line of YAML. Two identical clusters, one hardened and one not, produce
identical reports.

Stage 10 then scored them from lookup tables keyed on the STRIDE letter and the
component type — so 1,818 landed on High, and "High" stopped meaning anything.

In the new engine a rule fires only when a fact drawn from the manifest
satisfies its predicate:

```yaml
when:
  all:
    - {fact: container.privileged, op: is_true}
```

If no container is privileged, the rule produces nothing. The hardened test
fixture produces zero critical and zero high findings; the vulnerable one
produces 17 and 22. That gap is the point.

## Running the migration

```bash
threatforge migrate /path/to/directory/containing/stage7-dfd.json
```

The importer reads `architecture.json` and/or `stage7-dfd.json`, normalises the
old `Kind:namespace:name` ids to the canonical `k8s:Kind:namespace/name` URN
scheme so both files merge into one graph rather than two, rebuilds boundaries
and reachability, and runs the rules that do not require raw spec.

On your uploaded data:

```
Model  327 assets · 181 flows · 7 boundaries
Risk   1 critical · 0 high · 0 medium · 0 low · 180 info
```

The 548 nodes in the two files deduplicate to 327 real assets. The one critical
is a genuine finding — `tf-serving-ingress` terminates internet traffic without
TLS. The 180 info items flag heuristically-inferred edges for verification.

Control-based rules cannot fire here because the legacy JSON discarded the
`spec`. `controls.py` detects this and skips fact extraction for legacy assets
rather than inventing facts from missing data — otherwise every container would
be reported as running as root purely because no `securityContext` was
recorded.

## Recommended sequence

1. `threatforge migrate ./old-output` — confirm the graph matches what you
   expect, and compare against `stage7-dfd.json` node counts.
2. `threatforge scan /path/to/kubernetes-examples` — the real scan, against the
   original YAML. Expect the finding count to fall by roughly 95% and the
   remaining findings to have file:line provenance.
3. `threatforge baseline .` — accept the current state.
4. Wire in `.github/workflows/threat-model.yml`.
5. Work the critical and high findings down, then lower `gate.fail_on`.

## What to keep from the old scripts

Nothing needs to be kept, but two ideas from them survived deliberately:

- **Explicit stages with inspectable intermediate state.** `scan -v` prints
  per-stage timing and object counts, and `threat-model.json` contains the full
  graph, so you can still debug stage by stage.
- **JSON as the interchange format.** It is now an output rather than the
  coupling between stages, which is what allows a stage to be swapped without
  rewriting its neighbours.
