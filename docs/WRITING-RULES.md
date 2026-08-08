# Writing rules

Rules are YAML. Adding one requires no Python.

Put a file in `threatforge/rules/packs/`, or keep your own directory and point
`rules.extra_paths` at it in `.threatforge.yml`.

## Anatomy

```yaml
pack: my-org
description: Rules specific to our platform.

rules:
  - id: ORG-001                     # must be unique across all packs
    title: Workload deployed outside an approved namespace
    severity: medium                # critical | high | medium | low | info
    stride: [E]                     # S T R I D E — one or more
    confidence: likely              # confirmed | likely | possible
    applies_to:
      kind: [Deployment, StatefulSet]
    when:
      all:
        - {fact: namespace, op: not_in, value: [prod, staging, platform]}
    evidence:
      - fact: namespace
        text: "deployed to namespace '{{ namespace }}'"
        expected: "an approved namespace"
    description: >
      Why an attacker cares. Write this as what the attacker gains, not as a
      restatement of the rule title.
    remediation:
      summary: One sentence, imperative.
      guidance: >
        The nuance: what to do first, what breaks, what the better long-term
        answer is.
      patch: |
        metadata:
          namespace: platform
      effort: low                   # low | medium | high
      breaking_risk: medium         # low | medium | high
    references:
      cwe: [CWE-284]
      mitre: [T1078]
      cis: ["5.7.4"]
      nist: [AC-3]
      owasp: [K03]
    tags: [governance]
```

## `applies_to` filters

All filters are ANDed. Omit the block to evaluate every subject.

| Key | Matches |
|---|---|
| `provider` | `kubernetes`, `terraform`, `docker`, `compose`, `live`, `external`, `graph` |
| `kind` | `Deployment`, `Container`, `Service`, `aws_s3_bucket`, `DockerImage`, `ComposeService`, `DataFlow`, … |
| `element` | `process`, `data_store`, `external_entity`, `data_flow` |
| `tag` | fires if the asset has **any** of these tags |
| `all_tags` | fires only if it has **all** of them |
| `not_tag` | excludes assets with any of these tags |
| `kind_regex` | regex against the kind |

Filtering early matters for performance and for avoiding accidents: a rule with
no `applies_to` and a fact that happens to exist on flows too will fire on
flows.

## Predicates

`when` is a tree of `all` / `any` / `none` / `not` and leaves:

```yaml
when:
  all:
    - {fact: container.privileged, op: is_false}
    - any:
        - {fact: container.dangerous_caps, op: non_empty}
        - {fact: pod.host_network, op: is_true}
    - not: {fact: namespace, op: eq, value: kube-system}
```

### Operators

| Operator | True when |
|---|---|
| `is_true` / `is_false` | value is exactly `True` / `False` |
| `exists` / `absent` | value is / is not `None` |
| `eq` `ne` | equality |
| `gt` `gte` `lt` `lte` | numeric comparison (non-numeric → false) |
| `in` / `not_in` | value is / is not in the supplied list |
| `contains` / `not_contains` | supplied value is in the fact's list |
| `any_in` / `none_in` | list intersection |
| `non_empty` / `empty` | truthiness |
| `len_gt` / `len_lt` | list length |
| `regex` / `not_regex` | case-insensitive search |
| `glob` | fnmatch |

Note the difference between `absent` and `is_false`. `automountServiceAccountToken`
unset is not the same as set to `false` — the first defaults to true at runtime.
Use `{op: not_in, value: [false]}` when "unset or true" is what you mean.

## Available facts

`threatforge rules --json` lists rules; to see the facts for a specific asset:

```python
from threatforge import scan
m = scan(".")
a = m.assets["k8s:Container:shop/storefront/web"]
for k, v in sorted(a.facts.items()):
    if not k.startswith("_"):
        print(f"{k:40} {v}")
```

Common families:

| Prefix | Examples |
|---|---|
| *(bare)* | `kind` `name` `namespace` `element` `provider` `tags` `sensitivity` `exposure_hops` `internet_reachable` `blast_radius` `reaches_sensitive` |
| `container.` | `privileged` `run_as_root` `allow_priv_esc` `read_only_root_fs` `caps_added` `dangerous_caps` `drops_all` `image` `image_registry` `latest_tag` `unpinned_image` `no_limits` `plaintext_secret_env` `no_probes` `host_ports` |
| `pod.` | `host_network` `host_pid` `host_ipc` `host_paths` `sensitive_host_path` `container_runtime_socket` `has_seccomp` `service_account` `uses_default_sa` `automount_sa_token` `replicas` `single_replica` |
| `net.` | `has_ingress_policy` `has_egress_policy` |
| `rbac.` | `cluster_admin` `wildcard_verbs` `wildcard_resources` `reads_secrets` `writes_secrets` `escalation_paths` `verbs` `resources` |
| `svc.` | `type` `ports` `node_ports` `external_ips` `unrestricted_lb` `exposes_admin_port` |
| `ing.` | `tls` `hosts` `wildcard_host` `ssl_redirect` `has_auth` `has_rate_limit` `has_waf` |
| `secret.` / `configmap.` | `committed_to_repo` `keys` `is_sealed` / `secretish_keys` |
| `ns.` | `pss_enforce` `pss_is_restricted` `has_quota` `has_limit_range` |
| `tf.` | `public_acl` `publicly_accessible` `encrypted` `open_cidr` `iam_wildcard` `imdsv2_required` `logging_enabled` `is_data_store` `is_edge` |
| `df.` | `base_image` `base_is_latest` `runs_as_root` `add_remote` `pipe_to_shell` `hardcoded_secret_refs` `healthcheck` |
| `compose.` | `privileged` `host_network` `docker_socket` `published_ports` `dangerous_caps` `no_limits` |
| `flow.` | `kind` `protocol` `encrypted` `crosses_boundary` `trust_delta` `from_internet` `target_element` `target_sensitivity` `data_classes` `confidence` |

To add a fact, edit `controls.py`, set it with a `SourceRef` so findings can
cite it, and document it here.

## Interpolation

`{{ fact.name }}` works in `title`, `description`, `evidence.text`,
`remediation.summary`, and `remediation.guidance`. `{{ component }}` renders the
asset's display name. Lists are joined with commas.

## Choosing severity and confidence

They are independent axes and conflating them is the most common rule-authoring
mistake.

**Severity** is the worst realistic outcome if the weakness is exploited,
assuming no compensating controls. Do not pre-discount for "it's probably
internal" — `risk.py` does that with actual graph data.

**Confidence** is how certain you are the finding is real:

- `confirmed` — the manifest is unambiguous. `privileged: true` means privileged.
- `likely` — strong inference, small chance of a runtime override. A container
  with no `runAsUser` runs as root *unless* an admission controller mutates it.
- `possible` — heuristic or naming-based. Anything matched by regex on a name.
  These get an automatic likelihood penalty during scoring.

## Testing a rule

Add a case to the fixtures and assert both directions. A rule that has never
been proven to stay silent is a rule that will produce false positives.

```python
def test_my_rule_fires(vuln):
    assert any(f.rule_id == "ORG-001" for f in vuln.findings)

def test_my_rule_silent_on_hardened(hard):
    assert not [f for f in hard.findings if f.rule_id == "ORG-001"]
```

`test_rules_are_well_formed` already enforces that every non-info rule has a
title, description, predicate, evidence spec, STRIDE mapping, and remediation
summary — so a malformed rule fails the suite rather than shipping quietly.
