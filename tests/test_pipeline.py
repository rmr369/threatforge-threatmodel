"""
End-to-end and unit tests.

The most important test in this file is `test_hardened_is_quiet`: a scanner
that cannot stay silent on a well-configured system is a scanner nobody will
keep in their pipeline.
"""

from __future__ import annotations

import json
import os

import pytest

from threatforge import scan
from threatforge.config import DEFAULTS, load
from threatforge.gate import evaluate
from threatforge.model import Element, Severity
from threatforge.render import html, markdown, mermaid, sarif
from threatforge.rules.engine import PACK_DIR, RuleEngine, _eval_node

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vulnerable")
HARD = os.path.join(HERE, "fixtures", "hardened")


def _cfg(root):
    c = load(root)
    c["suppress"]["paths"] = []          # fixtures live under tests/
    return c


@pytest.fixture(scope="module")
def vuln():
    return scan(VULN, config=_cfg(VULN))


@pytest.fixture(scope="module")
def hard():
    return scan(HARD, config=_cfg(HARD))


# ---------------------------------------------------------------------------
# Signal-to-noise
# ---------------------------------------------------------------------------

def test_hardened_is_quiet(hard):
    """A correctly configured stack must not produce critical or high findings."""
    counts = hard.counts()
    assert counts["critical"] == 0, [f.rule_id for f in hard.active_findings
                                     if f.risk_level == Severity.CRITICAL]
    assert counts["high"] == 0, [f.rule_id for f in hard.active_findings
                                 if f.risk_level == Severity.HIGH]


def test_vulnerable_is_loud(vuln):
    counts = vuln.counts()
    assert counts["critical"] >= 8
    assert len(vuln.active_findings) > 40


def test_every_finding_has_evidence(vuln):
    for f in vuln.findings:
        assert f.evidence, f"{f.rule_id} produced no evidence"
        assert f.evidence[0].description


def test_findings_cite_a_source_file(vuln):
    """Evidence without provenance is an opinion."""
    missing = [f.rule_id for f in vuln.active_findings
               if f.component_type != "data_flow" and not f.primary_source.file]
    assert not missing, missing


def test_finding_ids_are_stable():
    a = scan(VULN, config=_cfg(VULN))
    b = scan(VULN, config=_cfg(VULN))
    assert {f.id for f in a.findings} == {f.id for f in b.findings}


# ---------------------------------------------------------------------------
# Specific detections
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id", [
    "TF-K8S-001",   # privileged
    "TF-K8S-004",   # docker socket
    "TF-K8S-006",   # host network
    "TF-K8S-015",   # plaintext secret env
    "TF-RBAC-001",  # cluster-admin
    "TF-NET-003",   # no TLS
    "TF-NET-008",   # exposed db port
    "TF-DATA-001",  # committed secret
    "TF-DATA-002",  # secret in configmap
    "TF-CLOUD-001",  # public bucket
    "TF-CLOUD-002",  # public db
    "TF-CLOUD-003",  # open security group
    "TF-CLOUD-009",  # imdsv1
    "TF-DKR-001",   # root image
    "TF-DKR-005",   # curl | sh
    "TF-CMP-002",   # compose docker socket
])
def test_rule_fires_on_vulnerable_fixture(vuln, rule_id):
    assert any(f.rule_id == rule_id for f in vuln.findings), \
        f"{rule_id} did not fire"


@pytest.mark.parametrize("rule_id", [
    "TF-K8S-001", "TF-K8S-002", "TF-K8S-003", "TF-K8S-010",
    "TF-K8S-011", "TF-K8S-013", "TF-K8S-014", "TF-K8S-016",
    "TF-NET-001", "TF-NET-003",
])
def test_rule_silent_on_hardened_fixture(hard, rule_id):
    hits = [f.component for f in hard.findings if f.rule_id == rule_id]
    assert not hits, f"{rule_id} false-positived on {hits}"


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def test_service_selector_resolves(vuln):
    edges = [(f.source, f.target) for f in vuln.flows if f.kind == "routes-to"]
    assert ("k8s:Service:shop/storefront", "k8s:Deployment:shop/storefront") in edges


def test_ingress_to_service_resolves(vuln):
    assert any(f.source == "k8s:Ingress:shop/storefront-ingress"
               and f.target == "k8s:Service:shop/storefront"
               for f in vuln.flows)


def test_secret_reference_resolves(vuln):
    assert any(f.target == "k8s:Secret:shop/shop-db" and f.kind in ("reads", "mounts")
               for f in vuln.flows)


def test_rbac_binding_resolves(vuln):
    assert any(f.source == "k8s:ServiceAccount:shop/postgres-sa"
               and f.target == "k8s:ClusterRole:None/shop-operator"
               or (f.kind == "granted" and "postgres-sa" in f.source)
               for f in vuln.flows)


def test_internet_reachability(vuln):
    ing = vuln.assets["k8s:Ingress:shop/storefront-ingress"]
    assert ing.facts["exposure_hops"] == 1
    dep = vuln.assets["k8s:Deployment:shop/storefront"]
    assert dep.facts["internet_reachable"] is True


def test_unreachable_asset_scores_lower(vuln):
    """Exposure must actually move the number, or the model is decoration."""
    reachable = [f for f in vuln.active_findings
                 if f.risk.exposure_hops is not None and f.severity == Severity.HIGH]
    isolated = [f for f in vuln.active_findings
                if f.risk.exposure_hops is None and f.severity == Severity.HIGH]
    if reachable and isolated:
        assert max(f.risk_score for f in reachable) > min(f.risk_score for f in isolated)


def test_trust_boundaries_nest(vuln):
    assert "boundary:internet" in vuln.boundaries
    assert "boundary:namespace:shop" in vuln.boundaries
    assert vuln.boundaries["boundary:namespace:shop"].parent == "boundary:cluster:default"


def test_boundary_crossing_flagged(vuln):
    crossing = [f for f in vuln.flows if f.crosses_boundary]
    assert crossing


def test_attack_path_reaches_a_secret(vuln):
    assert vuln.attack_paths
    targets = {p.target for p in vuln.attack_paths}
    assert any("Secret" in t or "postgres" in t for t in targets)
    top = vuln.attack_paths[0]
    assert top.hops[0].startswith("ext:")
    assert len(top.narrative) >= 2


def test_datastore_workload_reclassified(vuln):
    pg = vuln.assets["k8s:StatefulSet:shop/postgres"]
    assert pg.element == Element.DATA_STORE


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

def test_all_packs_load_cleanly():
    engine = RuleEngine.load([PACK_DIR])
    assert not engine.load_errors, engine.load_errors
    assert len(engine.rules) >= 50


def test_rules_are_well_formed():
    for r in RuleEngine.load([PACK_DIR]).rules:
        assert r.id.startswith("TF-"), r.id
        assert r.title and r.description, r.id
        assert r.when, f"{r.id} has no predicate -- it would fire on everything"
        assert r.evidence, f"{r.id} declares no evidence"
        if r.severity != Severity.INFO:
            assert r.stride, f"{r.id} has no STRIDE mapping"
            assert r.remediation.get("summary"), f"{r.id} has no remediation"


def test_rule_ids_unique():
    ids = [r.id for r in RuleEngine.load([PACK_DIR]).rules]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("node,facts,expected", [
    ({"fact": "a", "op": "is_true"}, {"a": True}, True),
    ({"fact": "a", "op": "is_true"}, {"a": None}, False),
    ({"fact": "a", "op": "is_false"}, {"a": False}, True),
    ({"fact": "a", "op": "non_empty"}, {"a": [1]}, True),
    ({"fact": "a", "op": "non_empty"}, {"a": []}, False),
    ({"fact": "a", "op": "gte", "value": 3}, {"a": 4}, True),
    ({"fact": "a", "op": "any_in", "value": ["x"]}, {"a": ["x", "y"]}, True),
    ({"fact": "a", "op": "not_in", "value": [False]}, {"a": None}, True),
    ({"all": [{"fact": "a", "op": "is_true"}, {"fact": "b", "op": "is_true"}]},
     {"a": True, "b": False}, False),
    ({"any": [{"fact": "a", "op": "is_true"}, {"fact": "b", "op": "is_true"}]},
     {"a": True, "b": False}, True),
    ({"not": {"fact": "a", "op": "is_true"}}, {"a": False}, True),
])
def test_predicate_operators(node, facts, expected):
    assert _eval_node(node, facts) is expected


def test_unknown_operator_is_caught():
    engine = RuleEngine.load([PACK_DIR])
    from threatforge.rules.engine import Rule
    r = Rule(id="X", title="x", when={"fact": "a", "op": "nope"})
    with pytest.raises(ValueError):
        r.evaluate({"a": 1})


# ---------------------------------------------------------------------------
# Risk
# ---------------------------------------------------------------------------

def test_risk_is_explained(vuln):
    for f in vuln.active_findings:
        assert 1 <= f.risk.likelihood <= 5
        assert 1 <= f.risk.impact <= 5
        assert f.risk_score == f.risk.likelihood * f.risk.impact
        assert f.risk.notes, f"{f.rule_id} has an unexplained score"


def test_findings_sorted_by_risk(vuln):
    scores = [f.risk_score for f in vuln.findings]
    assert scores == sorted(scores, reverse=True)


def test_suppression_by_path():
    cfg = load(VULN)
    cfg["suppress"]["paths"] = ["**/*.tf"]
    m = scan(VULN, config=cfg)
    assert all(not f.primary_source.file or not f.primary_source.file.endswith(".tf")
               for f in m.active_findings)


def test_suppression_by_rule():
    cfg = _cfg(VULN)
    cfg["suppress"]["rules"] = ["TF-K8S-001"]
    m = scan(VULN, config=cfg)
    assert all(f.rule_id != "TF-K8S-001" for f in m.active_findings)
    assert any(f.rule_id == "TF-K8S-001" and f.suppressed for f in m.findings)


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

def test_gate_fails_on_vulnerable(vuln):
    passed, report = evaluate(vuln, {"fail_on": "high", "max_new": 0})
    assert not passed
    assert report["reasons"]


def test_gate_passes_on_hardened(hard):
    passed, _ = evaluate(hard, {"fail_on": "high", "max_new": 0,
                                "fail_on_attack_path": False})
    assert passed


def test_gate_ratchet_accepts_baseline(vuln):
    baseline = {"accepted": {f.id: {"reason": "known"} for f in vuln.active_findings}}
    passed, report = evaluate(vuln, {"fail_on": "high", "max_new": 0,
                                     "fail_on_attack_path": False}, baseline)
    assert passed, report["reasons"]


def test_gate_none_disables_threshold(vuln):
    passed, _ = evaluate(vuln, {"fail_on": "none", "fail_on_attack_path": False})
    assert passed


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def test_sarif_is_valid_json_and_shaped(vuln):
    doc = json.loads(sarif.render(vuln))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"]
    for res in run["results"]:
        assert res["level"] in ("error", "warning", "note")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["threatforge/v1"]
        sev = float(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"])
        assert 0 <= sev <= 10


def test_html_is_self_contained(vuln):
    out = html.render(vuln)
    assert out.startswith("<!DOCTYPE html>")
    assert 'id="tf-data"' in out
    start = out.index('type="application/json">') + len('type="application/json">')
    end = out.index("</script>", start)
    payload = json.loads(out[start:end])
    assert len(payload["findings"]) == len(vuln.active_findings)
    # no unresolved python format placeholders
    assert "{title}" not in out and "{data}" not in out


def test_markdown_contains_the_essentials(vuln):
    md = markdown.render(vuln, max_findings=5)
    for section in ("# Threat model", "## Executive summary", "## Trust boundaries",
                    "## Attack paths", "## STRIDE coverage", "## Findings"):
        assert section in md


def test_mermaid_is_syntactically_plausible(vuln):
    d = mermaid.render_dfd(vuln)
    assert d.startswith("flowchart")
    assert "subgraph" in d
    assert d.count("[") == d.count("]")
    ap = mermaid.render_attack_path(vuln, 0)
    assert "==>" in ap


def test_mermaid_namespace_scope(vuln):
    d = mermaid.render_dfd(vuln, namespace="shop")
    assert "shop" in d


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_empty_directory_does_not_crash(tmp_path):
    m = scan(str(tmp_path))
    assert m.counts()["critical"] == 0
    assert len(m.findings) == 0


def test_malformed_yaml_is_reported_not_fatal(tmp_path):
    (tmp_path / "broken.yaml").write_text("kind: Pod\n  bad indent: [unclosed\n")
    (tmp_path / "good.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: ok}\n"
        "spec: {containers: [{name: c, image: nginx:latest}]}\n")
    m = scan(str(tmp_path))
    assert "k8s:Pod:default/ok" in m.assets
    assert any("parse failed" in e["message"] for e in m.errors)


def test_helm_templates_do_not_break_ingest(tmp_path):
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: {{ .Release.Name }}-api\n"
        "spec:\n  replicas: {{ .Values.replicas }}\n"
        "  template:\n    spec:\n      containers:\n"
        "        - name: api\n          image: repo/api:latest\n")
    m = scan(str(tmp_path))
    assert any(a.kind == "Deployment" for a in m.assets.values())


def test_json_round_trips(vuln):
    payload = json.loads(vuln.to_json())
    assert payload["summary"]["assets"] == len(vuln.assets)
    assert len(payload["findings"]) == len(vuln.findings)


def test_config_defaults_are_complete():
    for key in ("ingestors", "rules", "suppress", "gate", "output"):
        assert key in DEFAULTS


# ---------------------------------------------------------------------------
# CLI argument handling
# ---------------------------------------------------------------------------

def test_nonexistent_target_is_rejected(capsys, tmp_path):
    """Scanning a path that does not exist must fail loudly, not create it.

    Regression: an unexpanded '~/repos/app' on PowerShell used to produce a
    literal '~' directory containing an empty -- and therefore falsely clean --
    report.
    """
    from threatforge.cli import main
    missing = str(tmp_path / "does" / "not" / "exist")
    assert main(["--no-color", "scan", missing]) == 2
    assert not os.path.exists(missing), "scan target must not be created"
    assert "does not exist" in capsys.readouterr().err


def test_literal_tilde_gets_a_shell_hint(capsys, tmp_path):
    from threatforge.cli import main
    target = os.path.join(str(tmp_path), "~", "repos", "app")
    assert main(["--no-color", "scan", target]) == 2
    err = capsys.readouterr().err
    assert "not expanded by PowerShell" in err


def test_file_target_is_rejected(capsys, tmp_path):
    from threatforge.cli import main
    f = tmp_path / "app.yaml"
    f.write_text("kind: Pod\n")
    assert main(["--no-color", "scan", str(f)]) == 2
    assert "That is a file" in capsys.readouterr().err


def test_empty_target_warns_instead_of_reporting_clean(capsys, tmp_path):
    from threatforge.cli import main
    (tmp_path / "notes.txt").write_text("nothing to see")
    out_dir = tmp_path / "out"
    assert main(["--no-color", "scan", str(tmp_path), "-o", str(out_dir)]) == 0
    assert "no infrastructure was found" in capsys.readouterr().out
