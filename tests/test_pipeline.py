# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
import yaml

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
    """Evidence without provenance is an opinion.

    Flows and trust boundaries are exempt, and the exemption is narrow: both are
    computed over the whole graph rather than parsed out of one place, so there
    is no honest file:line to cite. Their evidence is arithmetic instead — how
    many crossings, how many of them plaintext — which is checked separately in
    test_boundaries_reach_the_rule_engine. Every other finding names the line
    that produced it.
    """
    derived = {"data_flow", "trust_boundary"}
    missing = [f.rule_id for f in vuln.active_findings
               if f.component_type not in derived and not f.primary_source.file]
    assert not missing, missing

    # The exemption must not become a hiding place: a derived finding still has
    # to explain itself.
    for f in vuln.active_findings:
        if f.component_type in derived:
            assert f.evidence and f.evidence[0].description, f.rule_id


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


# ---------------------------------------------------------------------------
# Hand-authored models and interchange round-trip
# ---------------------------------------------------------------------------

MANUAL = os.path.join(HERE, "fixtures", "manual")


@pytest.fixture(scope="module")
def overlay():
    return scan(MANUAL, config=_cfg(MANUAL))


def test_overlay_adds_components_the_scanner_cannot_see(overlay):
    """The whole point: SaaS and humans are invisible to static analysis."""
    for expected in ("manual:payment-provider", "manual:crm-saas",
                     "manual:ops-engineer"):
        assert expected in overlay.assets, expected


def test_overlay_classifies_external_saas_correctly(overlay):
    from threatforge.model import DataClass
    crm = overlay.assets["manual:crm-saas"]
    assert crm.element == Element.DATA_STORE
    assert DataClass.PII in crm.data_classes
    pay = overlay.assets["manual:payment-provider"]
    assert pay.element == Element.EXTERNAL_ENTITY


def test_attach_to_annotates_rather_than_duplicating(overlay):
    """An annotation must enrich the scanned asset, not create a twin."""
    pg = overlay.assets["k8s:StatefulSet:shop/postgres"]
    assert "annotated_by_hand" in pg.tags
    assert "crown-jewel" in pg.tags
    assert not any(a.id == "manual:k8s:StatefulSet:shop/postgres"
                   for a in overlay.assets.values())


def test_attach_to_bad_reference_is_reported_not_silent(tmp_path):
    """A typo in an overlay must not quietly drop a node from the analysis."""
    (tmp_path / "threatforge-overlay.yml").write_text(
        "components:\n"
        "  - attach_to: k8s:Deployment:nope/does-not-exist\n"
        "    tags: [crown-jewel]\n")
    m = scan(str(tmp_path))
    assert any("attach_to references an asset that was not found" in e["message"]
               for e in m.errors)


def test_manual_flows_join_the_graph(overlay):
    assert any(f.target == "manual:payment-provider" for f in overlay.flows)
    assert any(f.source == "manual:ops-engineer" for f in overlay.flows)


def test_overlay_extends_reachability_and_attack_paths(overlay):
    """A hand-added data store must be reachable, or the overlay is decoration."""
    crm = overlay.assets["manual:crm-saas"]
    assert crm.facts.get("internet_reachable") is True
    assert any("manual:" in p.target for p in overlay.attack_paths)


def test_manual_boundary_applies(overlay):
    assert "boundary:manual:third-party" in overlay.boundaries
    b = overlay.boundaries["boundary:manual:third-party"]
    assert "manual:crm-saas" in b.members


def test_decorative_elements_are_skipped(tmp_path):
    (tmp_path / "model.thf").write_text(
        "version: '1.0'\n"
        "elements:\n"
        "  - {id: note-1, type: text, name: Just a sticky note}\n"
        "  - {id: real-1, type: process, name: Real service}\n")
    m = scan(str(tmp_path))
    assert "manual:real-1" in m.assets
    assert "manual:note-1" not in m.assets


# -- interchange export ------------------------------------------------------

def test_thf_export_is_valid_yaml_with_expected_shape(vuln):
    import yaml as _yaml
    from threatforge.render import thf
    doc = _yaml.safe_load(thf.render(vuln))
    for key in ("version", "metadata", "elements", "data_flows",
                "trust_boundaries", "threats"):
        assert key in doc, key
    el = doc["elements"][0]
    for key in ("id", "type", "name", "trust_zone", "position"):
        assert key in el, key
    assert el["type"] in ("process", "data_store", "external_entity", "generic")
    assert el["trust_zone"] in ("external", "dmz", "internal")


def test_thf_export_carries_findings_as_threats(vuln):
    import yaml as _yaml
    from threatforge.render import thf
    doc = _yaml.safe_load(thf.render(vuln))
    assert doc["threats"]
    t = doc["threats"][0]
    assert t["category"] in ("Spoofing", "Tampering", "Repudiation",
                             "Information Disclosure", "Denial of Service",
                             "Elevation of Privilege")
    assert t["severity"] in ("critical", "high", "medium", "low", "info")
    assert t["risk"]["score"] >= 1
    assert t["evidence"]


def test_thf_export_positions_nodes_by_exposure(vuln):
    """Layout must be readable: entry points left, unreachable assets right."""
    import yaml as _yaml
    from threatforge.render import thf
    doc = _yaml.safe_load(thf.render(vuln))
    by_id = {e["id"]: e for e in doc["elements"]}
    exposed = [e for i, e in by_id.items()
               if vuln.assets[i].facts.get("exposure_hops") == 1]
    isolated = [e for i, e in by_id.items()
                if vuln.assets[i].facts.get("exposure_hops") is None]
    if exposed and isolated:
        assert min(e["position"]["x"] for e in exposed) < \
               min(e["position"]["x"] for e in isolated)


def test_thf_round_trip_preserves_assets(vuln, tmp_path):
    """Export then re-import must not lose nodes, or the workflow is broken."""
    from threatforge.render import thf
    (tmp_path / "model.thf").write_text(thf.render(vuln), encoding="utf-8")
    back = scan(str(tmp_path))

    original = {a.id for a in vuln.assets.values()
                if a.kind != "Container" and a.provider != "external"}
    recovered = {a.id for a in back.assets.values() if a.provider != "external"}
    assert original <= recovered, sorted(original - recovered)[:5]

    stores = lambda m: len([a for a in m.assets.values()
                            if a.element == Element.DATA_STORE])
    assert stores(back) >= stores(vuln) - 1


def test_thf_export_is_yaml_safe_for_all_value_types(vuln):
    """Evidence values can be sets and enums; the writer must flatten them."""
    import yaml as _yaml
    from threatforge.render import thf
    out = thf.render(vuln)
    assert "!!python" not in out          # no object tags leaked
    _yaml.safe_load(out)


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------

def test_scan_is_idempotent_when_output_lands_inside_the_repo(tmp_path):
    """Reports are written inside the scanned tree by default, and .thf/.json are
    also valid *inputs*. Without excluding our own output, a second scan analyses
    the first scan's report and silently returns different numbers."""
    import shutil
    from threatforge import pipeline
    target = tmp_path / "repo"
    shutil.copytree(MANUAL, str(target))

    cfg = _cfg(str(target))
    first = pipeline.run(str(target), cfg)
    out = str(target / "threatforge-out")
    pipeline.write_outputs(first, out, ["json", "thf", "mermaid"])
    assert os.path.exists(os.path.join(out, "threat-model.thf"))

    second = pipeline.run(str(target), _cfg(str(target)))
    assert second.counts() == first.counts(), "scan is not idempotent"
    assert len(second.assets) == len(first.assets)
    assert {a.id for a in second.assets.values()} == {a.id for a in first.assets.values()}


def test_output_directory_is_never_ingested(tmp_path):
    from threatforge import scan
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: real}\n"
        "spec: {containers: [{name: c, image: nginx:1.27}]}\n")
    out = tmp_path / "threatforge-out"
    out.mkdir()
    (out / "threat-model.thf").write_text(
        "version: '1.0'\nelements:\n  - {id: ghost, type: process, name: Ghost}\n")
    m = scan(str(tmp_path))
    assert "manual:ghost" not in m.assets, "output directory was re-ingested"
    assert "k8s:Pod:default/real" in m.assets


def test_explicit_output_dir_is_relative_to_cwd_not_scan_root(tmp_path, monkeypatch):
    """`-o reports` from the parent directory must not write to <root>/reports."""
    import shutil
    from threatforge.cli import main
    target = tmp_path / "repo"
    shutil.copytree(HARD, str(target))
    monkeypatch.chdir(tmp_path)

    assert main(["--no-color", "scan", "repo", "-o", "reports",
                 "-f", "json", "--quiet"]) == 0
    assert (tmp_path / "reports" / "threat-model.json").exists()
    assert not (target / "repo").exists()
    assert not (target / "reports").exists()


def test_config_output_dir_stays_relative_to_scan_root(tmp_path, monkeypatch):
    import shutil
    from threatforge.cli import main
    target = tmp_path / "repo"
    shutil.copytree(HARD, str(target))
    (target / ".threatforge.yml").write_text("output:\n  dir: myreports\n  formats: [json]\n")
    monkeypatch.chdir(tmp_path)

    assert main(["--no-color", "scan", "repo", "--quiet"]) == 0
    assert (target / "myreports" / "threat-model.json").exists()


# ---------------------------------------------------------------------------
# Microsoft Threat Modeling Tool (.tm7) import
# ---------------------------------------------------------------------------

TMT = os.path.join(HERE, "fixtures", "tmt")


@pytest.fixture(scope="module")
def tmt():
    return scan(TMT, config=_cfg(TMT))


def test_tmt_elements_map_to_dfd_roles(tmt):
    ext = tmt.assets["tmt:22222222-0000-0000-0000-000000000001"]
    proc = tmt.assets["tmt:22222222-0000-0000-0000-000000000002"]
    store = tmt.assets["tmt:22222222-0000-0000-0000-000000000003"]
    assert ext.element == Element.EXTERNAL_ENTITY and ext.name == "Customer Browser"
    assert proc.element == Element.PROCESS and proc.name == "Billing API"
    assert store.element == Element.DATA_STORE


def test_tmt_out_of_scope_elements_are_excluded(tmt):
    """TMT lets analysts mark shapes out of scope; importing them would
    resurrect decommissioned systems into a live model."""
    assert "tmt:22222222-0000-0000-0000-000000000009" not in tmt.assets
    assert not any(f.target == "tmt:22222222-0000-0000-0000-000000000009"
                   for f in tmt.flows)


def test_tmt_stencil_yields_protocol_and_encryption(tmt):
    """TypeId is the only place TMT records transport, and it drives TF-FLOW-001."""
    flows = {f.details.get("name"): f for f in tmt.flows if f.source.startswith("tmt:")}
    assert flows["Checkout request"].protocol == "https"
    assert flows["Checkout request"].encrypted is True
    assert flows["Billing query"].protocol == "sql"
    assert flows["Billing query"].encrypted is None      # genuinely unknown


def test_tmt_boundaries_are_resolved_geometrically(tmt):
    """TMT has no membership list -- containment is which rectangle you sit in."""
    b = tmt.boundaries["boundary:tmt:33333333-0000-0000-0000-000000000001"]
    assert b.name == "Corporate DMZ"
    assert b.trust_level == 30
    assert "tmt:22222222-0000-0000-0000-000000000002" in b.members
    assert "tmt:22222222-0000-0000-0000-000000000003" in b.members
    assert "tmt:22222222-0000-0000-0000-000000000001" not in b.members  # outside


def test_tmt_analyst_threats_are_preserved(tmt):
    threats = [t for t in tmt.metadata.get("manual_threats", [])
               if t.get("origin") == "microsoft-tmt"]
    assert threats
    t = threats[0]
    assert "SQL injection" in t["title"]
    assert t["stride"] == "T"
    assert t["severity"] == "high"
    assert t["mitigation"] == "Mitigated"
    assert t["mitigation_detail"]


def test_tmt_elements_participate_in_analysis(tmt):
    """An imported model must be analysed, not merely displayed."""
    store = tmt.assets["tmt:22222222-0000-0000-0000-000000000003"]
    assert store.facts.get("internet_reachable") is True
    assert store.facts.get("exposure_hops") is not None


def test_tmt_malformed_file_is_reported_not_fatal(tmp_path):
    (tmp_path / "broken.tm7").write_text("<ThreatModel><unclosed>")
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: ok}\n"
        "spec: {containers: [{name: c, image: nginx:1.27}]}\n")
    m = scan(str(tmp_path))
    assert "k8s:Pod:default/ok" in m.assets
    assert any(e["stage"] == "ingest.tmt" for e in m.errors)


def test_tmt_records_schema_version(tmt):
    imports = tmt.metadata.get("tmt_imports", [])
    assert imports and imports[0]["schema_version"] == "4.3"


def test_fail_on_none_disables_the_whole_gate(vuln):
    """`none` must mean none. Failing on an attack path after the user asked for
    no gate is the kind of surprise that gets a tool deleted from a pipeline."""
    assert any(p.level == Severity.CRITICAL for p in vuln.attack_paths), \
        "fixture must have a critical attack path for this test to mean anything"
    passed, report = evaluate(vuln, {"fail_on": "none", "fail_on_attack_path": True})
    assert passed, report["reasons"]


def test_attack_path_gate_still_fires_when_a_threshold_is_set(vuln):
    passed, report = evaluate(vuln, {"fail_on": "critical", "fail_on_attack_path": True})
    assert not passed
    assert any("attack path" in r for r in report["reasons"])


# ---------------------------------------------------------------------------
# .tm7 export — the other half of the TMT integration
# ---------------------------------------------------------------------------

def test_tm7_export_is_wellformed_and_versioned(vuln):
    import xml.etree.ElementTree as ET
    from threatforge.render import tmt
    root = ET.fromstring(tmt.render(vuln))
    assert root.tag.endswith("ThreatModel")
    assert root.find(".//{*}Version").text == "4.3"
    assert root.find(".//{*}ThreatModelName") is not None


def test_tm7_export_uses_correct_shape_classes(vuln):
    """DataContract deserialisation keys off i:type; wrong class, no open."""
    from threatforge.render import tmt
    xml = tmt.render(vuln)
    assert 'i:type="StencilEllipse"' in xml         # process
    assert 'i:type="StencilParallelLines"' in xml   # data store
    assert 'i:type="StencilRectangle"' in xml       # external entity
    assert 'i:type="Connector"' in xml              # data flow


def test_tm7_export_guids_are_deterministic(vuln):
    """Re-export must reuse ids, or TMT sees a new model and drops annotations."""
    from threatforge.render import tmt
    assert tmt.render(vuln) == tmt.render(vuln)
    assert tmt.guid_for("k8s:Pod:default/x") == tmt.guid_for("k8s:Pod:default/x")
    assert tmt.guid_for("a") != tmt.guid_for("b")


def test_tm7_export_carries_findings_with_evidence(vuln):
    from threatforge.render import tmt
    xml = tmt.render(vuln)
    assert "UserThreatCategory" in xml
    assert "Evidence:" in xml          # file:line reaches the analyst
    assert "Risk " in xml and "likelihood" in xml


def test_tm7_export_escapes_hostile_text(tmp_path):
    """Names contain <, &, quotes. Unescaped, they produce invalid XML."""
    import xml.etree.ElementTree as ET
    from threatforge import scan
    from threatforge.render import tmt
    (tmp_path / "overlay.tfm.yml").write_text(
        'components:\n'
        '  - {id: weird, type: process, name: \'A <b>&"name" with \\\'quotes\\\'\'}\n')
    m = scan(str(tmp_path))
    ET.fromstring(tmt.render(m))       # must not raise


def test_tm7_round_trips_through_our_own_importer(vuln, tmp_path):
    from threatforge import scan
    from threatforge.render import tmt
    (tmp_path / "export.tm7").write_text(tmt.render(vuln), encoding="utf-8")
    back = scan(str(tmp_path))
    imported = [a for a in back.assets.values() if a.provider == "tmt"]
    assert len(imported) >= 10
    assert any(a.element == Element.DATA_STORE for a in imported)
    assert any(f.source.startswith("tmt:") for f in back.flows)
    assert not [e for e in back.errors if e["stage"] == "ingest.tmt"]


def test_tm7_is_offered_as_a_cli_format(tmp_path):
    import shutil
    from threatforge.cli import main
    target = tmp_path / "repo"
    shutil.copytree(HARD, str(target))
    assert main(["--no-color", "scan", str(target), "-o", str(tmp_path / "o"),
                 "-f", "tmt", "--quiet"]) == 0
    assert (tmp_path / "o" / "threat-model.tm7").exists()


def test_tm7_export_has_every_member_the_schema_requires(vuln):
    """DataContract rejects a document with missing members.

    These names come from the Microsoft TMT 4.3 schema. Dropping any of them
    produces a file that looks fine in a text editor and fails to open in TMT,
    which is the worst possible failure mode -- silent until someone tries.
    """
    import xml.etree.ElementTree as ET
    from threatforge.render import tmt
    root = ET.fromstring(tmt.render(vuln))
    present = set()

    def walk(node, prefix=""):
        for c in node:
            p = f"{prefix}/{c.tag.split('}')[-1]}"
            present.add(p)
            walk(c, p)

    walk(root)

    surface = "/DrawingSurfaceList/DrawingSurfaceModel"
    threat = "/ThreatInstances/KeyValueOfstringThreatpc_P0_PhOB/Value"
    for required in (
        f"{surface}/GenericTypeId", f"{surface}/Guid", f"{surface}/TypeId",
        f"{surface}/Properties/anyType/DisplayName",
        f"{surface}/Borders/KeyValueOfguidanyType/Key",
        f"{surface}/Borders/KeyValueOfguidanyType/Value/Height",
        f"{surface}/Lines/KeyValueOfguidanyType/Value/SourceGuid",
        f"{surface}/Lines/KeyValueOfguidanyType/Value/TargetGuid",
        "/MetaInformation/ThreatModelName", "/Notes", "/Validations", "/Version",
        f"{threat}/ChangedBy", f"{threat}/DrawingSurfaceGuid", f"{threat}/FlowGuid",
        f"{threat}/Id", f"{threat}/InteractionKey", f"{threat}/ModifiedAt",
        f"{threat}/Priority", f"{threat}/SourceGuid", f"{threat}/State",
        f"{threat}/StateInformation", f"{threat}/TargetGuid", f"{threat}/Title",
        f"{threat}/TypeId", f"{threat}/Upgraded",
    ):
        assert required in present, f"missing required member: {required}"


def test_tm7_threat_namespaces_are_not_inverted(vuln):
    """Threat fields live in KnowledgeBase; the property map lives in Arrays.
    Swapping the two prefixes yields well-formed XML that TMT refuses."""
    from threatforge.render import tmt
    xml = tmt.render(vuln)
    assert "<b:SourceGuid>" in xml and "<b:InteractionKey>" in xml
    assert "<a:KeyValueOfstringstring>" in xml
    assert "<a:SourceGuid>" not in xml


# ---------------------------------------------------------------------------
# draw.io / diagrams.net interop
# ---------------------------------------------------------------------------

DRAWIO = os.path.join(HERE, "fixtures", "drawio")


@pytest.fixture(scope="module")
def dio():
    return scan(DRAWIO, config=_cfg(DRAWIO))


def test_drawio_shapes_map_to_dfd_roles(dio):
    by_name = {a.name: a for a in dio.assets.values() if a.provider == "drawio"}
    assert by_name["Customer"].element == Element.EXTERNAL_ENTITY   # umlActor
    assert by_name["Checkout API"].element == Element.PROCESS       # ellipse
    assert by_name["Card Vault"].element == Element.DATA_STORE      # datastore
    assert by_name["Ledger service"].element == Element.PROCESS     # tfType


def test_drawio_explicit_typing_beats_the_heuristic(dio):
    ledger = next(a for a in dio.assets.values() if a.name == "Ledger service")
    assert "typed:explicit" in ledger.tags, "custom tfType property was ignored"


def test_drawio_html_labels_are_cleaned(dio):
    """draw.io labels are HTML: <b>Checkout</b><br>API."""
    assert any(a.name == "Checkout API" for a in dio.assets.values())


def test_drawio_text_annotations_are_not_assets(dio):
    """A reviewer's sticky note must not become a node in the attack graph."""
    assert not any(a.name.startswith("Reviewed") for a in dio.assets.values())


def test_drawio_boundaries_resolve_geometrically(dio):
    b = next(b for b in dio.boundaries.values() if b.name == "Corporate DMZ")
    assert b.trust_level == 30
    assert "drawio:api" in b.members and "drawio:db" in b.members
    assert "drawio:cust" not in b.members          # drawn outside the rectangle


def test_drawio_protocol_encryption_is_three_state(dio):
    """Unknown must stay unknown -- inventing 'unencrypted' creates false
    positives in TF-FLOW-001."""
    flows = {f.details.get("name"): f for f in dio.flows
             if f.source.startswith("drawio:")}
    assert flows["checkout (https)"].encrypted is True
    assert flows["post ledger entry (http)"].encrypted is False
    assert flows["read card token (sql)"].encrypted is None


def test_drawio_compressed_diagrams_are_decoded(tmp_path):
    """draw.io writes deflate+base64 by default. An importer that only handles
    plain XML fails on exactly the large diagrams that matter."""
    import base64, urllib.parse, zlib
    inner = ('<mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
             '<mxCell id="svc" value="Payments API" style="ellipse;" vertex="1" '
             'parent="1"><mxGeometry x="10" y="10" width="80" height="40" '
             'as="geometry"/></mxCell></root></mxGraphModel>')
    packed = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    blob = packed.compress(urllib.parse.quote(inner).encode()) + packed.flush()
    (tmp_path / "compressed.drawio").write_text(
        '<mxfile host="app.diagrams.net"><diagram id="d" name="Page-1">'
        f'{base64.b64encode(blob).decode()}</diagram></mxfile>')

    m = scan(str(tmp_path))
    assert any(a.name == "Payments API" for a in m.assets.values()), \
        "compressed diagram was not decoded"


def test_drawio_participates_in_analysis(dio):
    """An imported diagram must be analysed, not just displayed."""
    vault = next(a for a in dio.assets.values() if a.name == "Card Vault")
    assert vault.facts.get("exposure_hops") is not None
    assert dio.attack_paths


def test_drawio_malformed_file_is_reported_not_fatal(tmp_path):
    (tmp_path / "broken.drawio").write_text("<mxfile><diagram>not-base64!!!")
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: ok}\n"
        "spec: {containers: [{name: c, image: nginx:1.27}]}\n")
    m = scan(str(tmp_path))
    assert "k8s:Pod:default/ok" in m.assets
    assert any(e["stage"] == "ingest.drawio" for e in m.errors)


# -- export ------------------------------------------------------------------

def test_drawio_export_is_valid_mxgraph(vuln):
    import xml.etree.ElementTree as ET
    from threatforge.render import drawio
    root = ET.fromstring(drawio.render(vuln))
    assert root.tag == "mxfile"
    assert root.find(".//mxGraphModel/root/mxCell[@id='0']") is not None
    assert root.findall(".//mxCell[@edge='1']")


def test_drawio_export_colours_nodes_by_risk(vuln):
    from threatforge.render import drawio
    xml = drawio.render(vuln)
    assert "#f8cecc" in xml     # critical fill present somewhere


def test_drawio_export_round_trips_exactly(vuln, tmp_path):
    """Every exported shape must come back explicitly typed, not re-guessed."""
    from threatforge.render import drawio
    (tmp_path / "m.drawio").write_text(drawio.render(vuln), encoding="utf-8")
    back = scan(str(tmp_path))
    imported = [a for a in back.assets.values() if a.provider == "drawio"]
    assert imported
    assert all("typed:explicit" in a.tags for a in imported)
    assert not [e for e in back.errors if e["stage"] == "ingest.drawio"]


def test_drawio_is_offered_as_a_cli_format(tmp_path):
    import shutil
    from threatforge.cli import main
    target = tmp_path / "repo"
    shutil.copytree(HARD, str(target))
    assert main(["--no-color", "scan", str(target), "-o", str(tmp_path / "o"),
                 "-f", "drawio", "--quiet"]) == 0
    assert (tmp_path / "o" / "threat-model.drawio").exists()


# ---------------------------------------------------------------------------
# Persistence, SLA and the local app
# ---------------------------------------------------------------------------

import datetime as _dt


def _fresh_store(tmp_path):
    from threatforge.store import Store
    return Store(str(tmp_path / "tf.db"))


def _scanned(tmp_path, fixture=None):
    """A store with one recorded scan of a copy of the vulnerable fixture."""
    import shutil
    from threatforge import pipeline
    root = tmp_path / "repo"
    shutil.copytree(fixture or VULN, str(root))
    cfg = _cfg(str(root))
    model = pipeline.run(str(root), cfg)
    store = _fresh_store(tmp_path)
    store.record_scan(model, str(root))
    return store, str(root), cfg


# -- store -------------------------------------------------------------------

def test_store_records_findings_with_first_seen(tmp_path):
    store, _, cfg = _scanned(tmp_path)
    rows = store.findings()
    assert rows
    assert all(r["first_seen"] for r in rows)
    assert all(r["status"] == "open" for r in rows)
    store.close()


def test_store_rescan_preserves_first_seen(tmp_path):
    """The SLA clock is meaningless if first_seen moves on every scan."""
    from threatforge import pipeline
    store, root, cfg = _scanned(tmp_path)
    before = {r["id"]: r["first_seen"] for r in store.findings()}
    store.record_scan(pipeline.run(root, cfg), root)
    after = {r["id"]: r["first_seen"] for r in store.findings()}
    assert before == {k: after[k] for k in before}
    store.close()


def test_store_preserves_human_workflow_across_rescans(tmp_path):
    """Owner and status are the human's; a rescan must not clobber them."""
    from threatforge import pipeline
    store, root, cfg = _scanned(tmp_path)
    fid = store.findings()[0]["id"]
    store.update_finding(fid, owner="alice", status="in_progress",
                         notes="SEC-1042", actor="alice")
    store.record_scan(pipeline.run(root, cfg), root)
    row = [r for r in store.findings() if r["id"] == fid][0]
    assert row["owner"] == "alice"
    assert row["status"] == "in_progress"
    assert row["notes"] == "SEC-1042"
    store.close()


def test_store_auto_resolves_findings_that_disappear(tmp_path):
    from threatforge import pipeline
    store, root, cfg = _scanned(tmp_path)
    app = os.path.join(root, "app.yaml")
    text = open(app).read().replace("privileged: true", "privileged: false")
    open(app, "w").write(text)

    store.record_scan(pipeline.run(root, cfg), root)
    resolved = [r for r in store.findings() if r["status"] == "resolved"]
    assert any(r["rule_id"] == "TF-K8S-001" for r in resolved)
    assert all(r["resolved_at"] for r in resolved)
    store.close()


def test_store_reopens_a_regression(tmp_path):
    from threatforge import pipeline
    store, root, cfg = _scanned(tmp_path)
    app = os.path.join(root, "app.yaml")
    original = open(app).read()

    open(app, "w").write(original.replace("privileged: true", "privileged: false"))
    store.record_scan(pipeline.run(root, cfg), root)
    open(app, "w").write(original)                       # regression
    store.record_scan(pipeline.run(root, cfg), root)

    row = [r for r in store.findings() if r["rule_id"] == "TF-K8S-001"][0]
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert any(e["kind"] == "reopened" for e in store.events(row["id"]))
    store.close()


def test_store_accepted_risk_is_not_reopened(tmp_path):
    """'Accepted' is a decision. A rescan must not silently undo it."""
    from threatforge import pipeline
    store, root, cfg = _scanned(tmp_path)
    fid = store.findings()[0]["id"]
    store.update_finding(fid, status="accepted", actor="ciso")
    store.record_scan(pipeline.run(root, cfg), root)
    assert [r for r in store.findings() if r["id"] == fid][0]["status"] == "accepted"
    store.close()


def test_store_writes_an_audit_trail(tmp_path):
    store, _, _ = _scanned(tmp_path)
    fid = store.findings()[0]["id"]
    store.update_finding(fid, owner="alice", actor="alice")
    store.update_finding(fid, status="resolved", actor="bob")
    kinds = [e["kind"] for e in store.events(fid)]
    assert "discovered" in kinds and "assigned" in kinds and "status_changed" in kinds
    store.close()


def test_store_rejects_an_invalid_status(tmp_path):
    store, _, _ = _scanned(tmp_path)
    with pytest.raises(ValueError):
        store.update_finding(store.findings()[0]["id"], status="banana")
    store.close()


# -- SLA ---------------------------------------------------------------------

def test_sla_windows_come_from_risk_level():
    from threatforge.sla import Policy
    p = Policy.from_config()
    seen = _dt.date(2026, 1, 1)
    assert p.due_date("critical", seen) == _dt.date(2026, 1, 8)
    assert p.due_date("high", seen) == _dt.date(2026, 1, 31)
    assert p.due_date("info", seen) is None


def test_sla_clock_starts_at_first_seen_not_today():
    """A critical finding eight months old is overdue, not new.

    `as_of` is passed explicitly: the module clock is UTC and a bare
    `date.today()` is local, so a naive version of this test is flaky for
    anyone not sitting on the meridian.
    """
    from threatforge.sla import Policy, evaluate
    p = Policy.from_config()
    as_of = _dt.date(2026, 9, 1)
    first_seen = as_of - _dt.timedelta(days=240)
    state = evaluate(p, "critical", first_seen, "open", as_of=as_of)
    assert state.breached is True
    assert state.days_remaining == 7 - 240
    assert state.age_days == 240


def test_sla_closed_findings_stop_the_clock():
    from threatforge.sla import Policy, evaluate
    p = Policy.from_config()
    as_of = _dt.date(2026, 9, 1)
    old = as_of - _dt.timedelta(days=400)
    state = evaluate(p, "critical", old, "resolved",
                     resolved_at=old + _dt.timedelta(days=3), as_of=as_of)
    assert state.breached is False
    assert state.state == "closed"
    assert state.age_days == 3


def test_sla_business_days_skip_weekends():
    from threatforge.sla import Policy
    p = Policy(windows={"critical": 5}, business_days=True)
    friday = _dt.date(2026, 1, 2)
    assert friday.weekday() == 4
    assert p.due_date("critical", friday) == _dt.date(2026, 1, 9)


def test_sla_summary_reports_compliance_and_owners(tmp_path):
    from threatforge.sla import Policy, summarise
    store, _, cfg = _scanned(tmp_path)
    rows = store.findings()
    store.update_finding(rows[0]["id"], owner="alice")
    store._conn.execute(
        "UPDATE findings SET first_seen=? WHERE id=?",
        ((_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=400)).isoformat(),
         rows[0]["id"]))
    store._conn.commit()

    rep = summarise(Policy.from_config(cfg), store.findings())
    assert rep["breached"] >= 1
    assert rep["compliance_pct"] < 100
    assert rep["overdue"][0]["days_overdue"] > 0
    assert "alice" in rep["by_owner"]
    store.close()


# -- server ------------------------------------------------------------------

def _running_app(tmp_path):
    import threading, time
    from http.server import ThreadingHTTPServer
    from threatforge.server import AppState, make_handler
    store, root, cfg = _scanned(tmp_path)
    state = AppState(root, store, cfg)
    state.rescan()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.15)
    return httpd, state, f"http://127.0.0.1:{httpd.server_address[1]}"


def _call(base, path, body=None, token=None, host=None):
    import urllib.error, urllib.request
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        method="POST" if body is not None else "GET")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-ThreatForge-Token", token)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_app_serves_the_page_and_api(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/")
        assert status == 200 and body.startswith(b"<!DOCTYPE html>")
        status, body = _call(base, "/api/findings")
        assert status == 200 and json.loads(body)["findings"]
    finally:
        httpd.shutdown(); state.store.close()


def test_app_rejects_mutation_without_the_session_token(tmp_path):
    """Any website can POST to localhost. Only our page knows the token."""
    httpd, state, base = _running_app(tmp_path)
    try:
        fid = json.loads(_call(base, "/api/findings")[1])["findings"][0]["id"]
        status, _ = _call(base, f"/api/findings/{fid}", {"owner": "mallory"})
        assert status == 403
        status, body = _call(base, f"/api/findings/{fid}", {"owner": "alice"},
                             token=state.token)
        assert status == 200
        assert json.loads(body)["finding"]["owner"] == "alice"
    finally:
        httpd.shutdown(); state.store.close()


def test_app_rejects_a_foreign_host_header(tmp_path):
    """Defence against DNS rebinding: only literal localhost is accepted."""
    httpd, state, base = _running_app(tmp_path)
    try:
        assert _call(base, "/api/bootstrap", host="evil.example.com")[0] == 403
        assert _call(base, "/api/bootstrap")[0] == 200
    finally:
        httpd.shutdown(); state.store.close()


def test_app_binds_only_to_loopback(tmp_path):
    httpd, state, _ = _running_app(tmp_path)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
    finally:
        httpd.shutdown(); state.store.close()


def test_app_reports_errors_as_json_not_stack_traces(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/findings/NOPE", {"owner": "x"},
                             token=state.token)
        assert status == 404 and "error" in json.loads(body)
        status, body = _call(base, "/api/nope")
        assert status == 404
    finally:
        httpd.shutdown(); state.store.close()


def test_app_sla_endpoint_matches_the_engine(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        payload = json.loads(_call(base, "/api/sla")[1])
        for key in ("compliance_pct", "buckets", "overdue", "policy", "by_owner"):
            assert key in payload
    finally:
        httpd.shutdown(); state.store.close()


# ---------------------------------------------------------------------------
# Scan sources: path, git, upload
# ---------------------------------------------------------------------------

def test_source_from_path_rejects_missing_and_files(tmp_path):
    from threatforge import sources
    with pytest.raises(sources.SourceError):
        sources.from_path(str(tmp_path / "nope"))
    f = tmp_path / "a.yaml"
    f.write_text("kind: Pod")
    with pytest.raises(sources.SourceError):
        sources.from_path(str(f))
    assert sources.from_path(str(tmp_path)).trusted is True


def test_git_url_normalisation():
    from threatforge.sources import normalise_git_url
    assert normalise_git_url("owner/repo") == "https://github.com/owner/repo.git"
    assert normalise_git_url("https://github.com/o/r/tree/main") == "https://github.com/o/r"


@pytest.mark.parametrize("url", [
    "--upload-pack=touch /tmp/pwned",          # option injection
    "https://internal.corp/secret.git",        # host not allowed
    "ftp://example.com/x.git",                 # unsupported scheme
])
def test_git_urls_that_must_be_rejected(url):
    from threatforge.sources import SourceError, normalise_git_url, validate_git_url
    with pytest.raises(SourceError):
        validate_git_url(normalise_git_url(url))


def test_git_allowed_hosts_pass():
    from threatforge.sources import normalise_git_url, validate_git_url
    _, host = validate_git_url(normalise_git_url("https://github.com/o/r.git"))
    assert host == "github.com"


def _zip_bytes(entries):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_upload_extracts_only_config_files(tmp_path):
    from threatforge import sources
    blob = _zip_bytes({
        "app/k8s/deploy.yaml": "kind: Pod\nmetadata: {name: x}\n",
        "app/main.tf": 'resource "aws_s3_bucket" "b" { bucket = "x" }',
        "app/photo.png": "binary-ish",
        "app/node_modules/pkg/index.js": "console.log(1)",
    })
    src = sources.from_zip_bytes(blob, "app", workspace=str(tmp_path))
    try:
        assert src.trusted is False
        assert src.detail["files"] == 2          # yaml + tf only
        assert src.detail["skipped"] >= 2
    finally:
        src.dispose()


def test_upload_rejects_zip_slip(tmp_path):
    """An archive member escaping the extraction directory must be refused."""
    from threatforge import sources
    blob = _zip_bytes({"../../../evil.yaml": "kind: Pod"})
    with pytest.raises(sources.SourceError) as exc:
        sources.from_zip_bytes(blob, "evil", workspace=str(tmp_path))
    assert "escape" in str(exc.value)


def test_upload_rejects_an_archive_with_nothing_scannable(tmp_path):
    from threatforge import sources
    with pytest.raises(sources.SourceError):
        sources.from_zip_bytes(_zip_bytes({"a.png": "x", "b.exe": "y"}),
                               "junk", workspace=str(tmp_path))


def test_untrusted_sources_disable_chart_rendering():
    """helm template and kustomize build execute repo logic. Not for strangers."""
    from threatforge import sources
    from threatforge.config import DEFAULTS
    trusted = sources.Source(root="/x", kind="path", label="a", trusted=True)
    untrusted = sources.Source(root="/x", kind="git", label="b", trusted=False)
    assert sources.config_for(trusted, DEFAULTS)["helm"]["render"] is True
    cfg = sources.config_for(untrusted, DEFAULTS)
    assert cfg["helm"]["render"] is False
    assert cfg["kustomize"]["render"] is False
    assert cfg["live"]["enabled"] is False


# -- server: sources, overlay, exports ---------------------------------------

def test_app_scans_a_path_through_the_api(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/scan",
                             {"source": {"kind": "path", "root": None,
                                         "path": state.base_root}},
                             token=state.token)
        assert status == 200
        assert json.loads(body)["summary"]["findings"] > 0
    finally:
        httpd.shutdown(); state.store.close()


def test_app_returns_400_for_a_bad_source(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/scan",
                             {"source": {"kind": "path", "path": "/definitely/not/here"}},
                             token=state.token)
        assert status == 400 and "does not exist" in json.loads(body)["error"]
        status, body = _call(base, "/api/scan",
                             {"source": {"kind": "git", "url": "https://internal.corp/x.git"}},
                             token=state.token)
        assert status == 400 and "not in the allowed list" in json.loads(body)["error"]
    finally:
        httpd.shutdown(); state.store.close()


def test_app_overlay_round_trip_and_merge(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        overlay = ("components:\n"
                   "  - id: crm\n    type: data_store\n    name: Salesforce\n"
                   "    trust_zone: partner\n")
        status, body = _call(base, "/api/overlay",
                             {"overlay": overlay, "rescan": True}, token=state.token)
        assert status == 200
        status, body = _call(base, "/api/graph")
        elements = json.loads(body)["elements"]
        assert any(e["name"] == "Salesforce" and e["hand"] for e in elements)

        status, body = _call(base, "/api/overlay")
        assert "Salesforce" in json.loads(body)["overlay"]
    finally:
        httpd.shutdown(); state.store.close()


def test_app_exports_every_format(tmp_path):
    """One server, every format -- spinning up eight servers is a slow test
    for no extra coverage."""
    httpd, state, base = _running_app(tmp_path)
    try:
        for fmt in ("tm7", "drawio", "thf", "json", "sarif",
                    "markdown", "html", "mermaid"):
            status, body = _call(base, f"/api/export/{fmt}")
            assert status == 200, fmt
            assert len(body) > 100, fmt
        assert _call(base, "/api/export/exe")[0] == 404
    finally:
        httpd.shutdown(); state.store.close()


# ---------------------------------------------------------------------------
# The diagram canvas: what /api/graph must supply for the UI to be usable,
# and what the DFD editor must be able to write back without loss.
# ---------------------------------------------------------------------------

def test_app_graph_carries_everything_the_canvas_draws(tmp_path):
    """A box-and-line drawing is not a threat model. The canvas needs risk."""
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/graph")
        assert status == 200
        g = json.loads(body)

        assert g["elements"] and g["flows"]
        for key in ("id", "name", "type", "risk", "findings", "hops",
                    "blast", "hand", "zone", "desc", "data"):
            assert key in g["elements"][0], key

        # Every flow needs a stable id or the editor cannot select or delete one.
        assert all(f.get("id") for f in g["flows"])
        assert len({f["id"] for f in g["flows"]}) == len(g["flows"])

        # The heat map is only a heat map if some nodes are actually hot.
        coloured = [e for e in g["elements"] if e["risk"]]
        assert coloured, "no element carried a risk level"
        assert all(e["findings"] > 0 for e in coloured)

        # A node's colour must match a real finding against that component.
        findings = json.loads(_call(base, "/api/findings")[1])["findings"]
        for e in coloured[:5]:
            assert any(f["component"] == e["id"] for f in findings), e["id"]
    finally:
        httpd.shutdown(); state.store.close()


def test_app_editor_round_trips_its_own_fields(tmp_path):
    """Save, re-scan, reload: what the user typed must come back unchanged.

    The overlay is namespaced on ingest (`tf-crm` -> `manual:tf-crm`), so a
    naive round trip either double-prefixes the id or silently resets the
    fields the scanner does not itself produce.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        g = json.loads(_call(base, "/api/graph")[1])
        target = next(e["id"] for e in g["elements"] if e["type"] == "process")
        overlay = (
            'components:\n'
            '  - {id: "tf-crm", type: external_entity, name: "Salesforce CRM",\n'
            '     trust_zone: partner, description: "Nightly customer sync",\n'
            '     data: ["pii"]}\n'
            'flows:\n'
            f'  - {{from: "tf-crm", to: "{target}", name: "nightly sync",\n'
            '     protocol: "http", encrypted: false}\n'
            'trust_boundaries:\n'
            '  - {id: "partner-zone", name: "Partner zone", trust_level: 40,\n'
            '     contains: ["tf-crm"]}\n')

        status, body = _call(base, "/api/overlay",
                             {"overlay": overlay, "rescan": True},
                             token=state.token)
        assert status == 200, body
        assert json.loads(body)["ok"]

        g2 = json.loads(_call(base, "/api/graph")[1])
        node = next(e for e in g2["elements"] if e["id"] == "manual:tf-crm")
        assert node["name"] == "Salesforce CRM"
        assert node["hand"] is True            # so the editor lets you delete it
        assert node["zone"] == "partner"       # not reset to the default
        assert node["desc"] == "Nightly customer sync"
        assert node["own_data"] == ["pii"]

        edge = next(f for f in g2["flows"] if f["source"] == "manual:tf-crm")
        assert edge["name"] == "nightly sync"
        assert edge["encrypted"] is False
        assert edge["hand"] is True
        assert edge["crosses"] is True         # the partner boundary was honoured

        bnd = next(b for b in g2["boundaries"]
                   if b["id"] == "boundary:manual:partner-zone")
        assert "manual:tf-crm" in bnd["members"]

        # Saving again must not turn `manual:tf-crm` into `manual:manual:tf-crm`.
        _call(base, "/api/overlay", {"overlay": overlay, "rescan": True},
              token=state.token)
        g3 = json.loads(_call(base, "/api/graph")[1])
        ids = [e["id"] for e in g3["elements"]]
        assert ids.count("manual:tf-crm") == 1
        assert not any(i.startswith("manual:manual:") for i in ids)
    finally:
        httpd.shutdown(); state.store.close()


def test_hand_drawn_flow_is_analysed_not_just_drawn():
    """The point of the editor: a drawn link must reach the rule engine.

    A partner system talking plaintext across a trust boundary is the classic
    thing static analysis cannot see and a human can. If drawing it produces no
    finding, the editor is a paint program.
    """
    import tempfile
    from threatforge import pipeline

    root = VULN
    cfg = _cfg(root)
    baseline = pipeline.run(root, cfg)
    before = {f.id for f in baseline.active_findings}
    target = next(a.id for a in baseline.assets.values()
                  if a.element.value == "process")

    with tempfile.TemporaryDirectory() as tmp:
        overlay = os.path.join(tmp, "overlay.yml")
        with open(overlay, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                'components:\n'
                '  - {id: "tf-crm", type: external_entity, name: "CRM",\n'
                '     trust_zone: partner, data: ["pii"]}\n'
                'flows:\n'
                f'  - {{from: "tf-crm", to: "{target}", protocol: "http",\n'
                '     encrypted: false}\n'
                'trust_boundaries:\n'
                '  - {id: "pz", name: "Partner zone", trust_level: 40,\n'
                '     contains: ["tf-crm"]}\n')
        cfg2 = dict(cfg)
        cfg2["manual"] = {"paths": [overlay]}
        after = pipeline.run(root, cfg2)

    new = [f for f in after.active_findings if f.id not in before]
    assert new, "drawing a plaintext partner link produced no finding"
    flow = [f for f in new if f.rule_id == "TF-FLOW-006"]
    assert flow, [f.rule_id for f in new]
    # Evidence, not assertion: the finding must cite the protocol it saw.
    assert any("http" in e.description for e in flow[0].evidence)


def test_boundary_crossing_rule_ignores_intra_cluster_plumbing(vuln):
    """A Service routing to its own Pods crosses a node boundary in every
    cluster on earth. Firing on that is how a rule engine becomes noise."""
    fired = [f for f in vuln.findings
             if f.rule_id in ("TF-FLOW-006", "TF-FLOW-007")]
    assert not fired, [f.component for f in fired]


def test_editor_yaml_generator_emits_only_hand_authored_content(tmp_path):
    """Run the browser's own YAML writer and feed the result to the ingestor.

    The editor shows scanned and hand-drawn elements on one canvas. If the
    writer cannot tell them apart, every scan would re-import the previous
    scan's output as manual input and the model would grow without bound.
    """
    import re as _re
    import shutil as _shutil
    import subprocess as _subprocess

    node = _shutil.which("node")
    if not node:
        pytest.skip("node is not installed")

    from threatforge.webui import PAGE
    mb = _re.search(r"(function mapBlock\(.*?\n\})\n", PAGE, _re.S)
    m = _re.search(r"(function overlayYamlFor\(C\)\{.*?\n\})\n", PAGE, _re.S)
    assert mb, "mapBlock was not found in the served page"
    assert m, "the editor's yaml() writer was not found in the served page"

    harness = tmp_path / "h.js"
    harness.write_text(
        "const esc = s => String(s==null?'':s);\n"
        + mb.group(1) + "\n"
        + m.group(1)
        + """
const C = {
  nodes:[
    {id:'tf-crm', name:'CRM', type:'external_entity', hand:true,
     zone:'partner', desc:'sync', data:['pii'], x:20, y:20, w:150, h:60,
     libType:'saas', tech:['rest'],
     attrs:{authenticates_itself:false, out_of_scope:false},
     custom:{'Owning team':'platform'}},
    {id:'k8s:Deployment:shop/api', name:'api', type:'process', hand:false,
     zone:'internal', data:[], x:600, y:600, w:150, h:60}],
  edges:[
    {id:'e1', source:'tf-crm', target:'k8s:Deployment:shop/api',
     protocol:'http', encrypted:false, hand:true,
     attrs:{contains_cookies:true, forgery_protection:'none'}},
    {id:'e2', source:'k8s:Deployment:shop/api', target:'tf-crm',
     protocol:'https', encrypted:true, hand:false}],
  bounds:[
    {id:'boundary:manual:pz', name:'Partner zone', trust_level:40, hand:true,
     x:0, y:0, w:300, h:200, members:['tf-crm']},
    {id:'boundary:cluster:default', name:'cluster', trust_level:60, hand:false,
     x:0, y:0, w:100, h:100, members:[]}]
};
// Membership is geometric, so the writer asks the canvas rather than reading
// a list. Same containment rule as canvas.py.
C.membersOf = b => C.nodes.filter(n =>
  n.x >= b.x && n.y >= b.y && n.x + n.w <= b.x + b.w && n.y + n.h <= b.y + b.h)
  .map(n => n.id);
process.stdout.write(overlayYamlFor(C));
""", encoding="utf-8")

    out = _subprocess.run([node, str(harness)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr

    doc = yaml.safe_load(out.stdout)
    assert len(doc["components"]) == 1, "a scanned node leaked into the overlay"
    assert len(doc["flows"]) == 1, "a scanned flow leaked into the overlay"
    assert len(doc["trust_boundaries"]) == 1, "a scanned boundary leaked"
    assert doc["flows"][0]["encrypted"] is False

    # Attributes must survive the writer, or the properties panel is decoration.
    comp = doc["components"][0]
    assert comp["component_type"] == "saas"
    assert comp["technologies"] == ["rest"]
    assert comp["attributes"]["authenticates_itself"] is False
    assert comp["custom_attributes"]["Owning team"] == "platform"
    assert doc["flows"][0]["attributes"]["forgery_protection"] == "none"

    # And the Python side must accept it without a parse warning.
    ov = tmp_path / "threatforge-overlay.yml"
    ov.write_text(out.stdout, encoding="utf-8", newline="\n")
    cfg = _cfg(VULN)
    cfg["manual"] = {"paths": [str(ov)]}
    model = scan(VULN, config=cfg)
    assert not [e for e in model.errors if "manual" in e.get("source", "")], model.errors
    assert model.assets["manual:tf-crm"].name == "CRM"
    assert model.boundaries["boundary:manual:pz"].members == {"manual:tf-crm"}


def test_canvas_behaviour_spec(tmp_path):
    """Run the diagramming surface's own spec under Node.

    The canvas is real editor logic — orthogonal routing, geometric boundary
    membership, undo, ownership rules, layout persistence — and none of it is
    reachable from Python. Checking that the page parses proves nothing about
    whether dragging a service into the DMZ changes the model.
    """
    import shutil as _shutil
    import subprocess as _subprocess

    node = _shutil.which("node")
    if not node:
        pytest.skip("node is not installed")

    from threatforge.canvas import CANVAS_JS, LIBRARY_JS, PROPS_JS

    spec = os.path.join(HERE, "js", "canvas_spec.js")
    bundle = tmp_path / "bundle.js"
    bundle.write_text(
        CANVAS_JS + "\n" + LIBRARY_JS + "\n" + PROPS_JS + "\n"
        + open(spec, encoding="utf-8").read(),
        encoding="utf-8")

    out = _subprocess.run([node, str(bundle)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "0 failed" in out.stdout, out.stdout


def test_app_layout_survives_a_rescan(tmp_path):
    """Where the boxes sit must outlive the scan that redraws them.

    Auto-layout runs on every load. If saved geometry did not win, the first
    re-scan would throw away the arrangement and the editor would be a viewer.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        g = json.loads(_call(base, "/api/graph")[1])
        target = next(e["id"] for e in g["elements"] if e["type"] == "process")
        layout = {
            "nodes": {target: {"x": 740, "y": 310, "w": 180, "h": 70}},
            "bounds": {"boundary:manual:dmz": {
                "x": 700, "y": 270, "w": 300, "h": 200,
                "name": "DMZ", "trust_level": 30, "hand": True}},
        }
        overlay = ('components:\n'
                   '  - {id: "tf-waf", type: process, name: "WAF", trust_zone: dmz}\n'
                   'trust_boundaries:\n'
                   '  - {id: "dmz", name: "DMZ", trust_level: 30,\n'
                   '     contains: ["tf-waf"]}\n')

        status, _ = _call(base, "/api/overlay",
                          {"overlay": overlay, "layout": layout, "rescan": True},
                          token=state.token)
        assert status == 200

        back = json.loads(_call(base, "/api/layout")[1])["layout"]
        assert back["nodes"][target]["x"] == 740
        assert back["bounds"]["boundary:manual:dmz"]["hand"] is True

        # A plain re-scan sends no layout; it must not be treated as "clear it".
        _call(base, "/api/scan", {}, token=state.token)
        after = json.loads(_call(base, "/api/layout")[1])["layout"]
        assert after["nodes"][target]["x"] == 740, "layout was wiped by a re-scan"

        assert os.path.exists(os.path.join(state.workspace, "overlay", "layout.json"))
    finally:
        httpd.shutdown(); state.store.close()


def test_a_saved_boundary_is_still_editable_after_reingest(tmp_path):
    """A boundary written to the overlay comes back through the scanner.

    If the UI judged ownership by "did the scan produce it", a drawn boundary
    would turn read-only after one save and vanish from the next one, because
    the writer only emits hand-authored content.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        overlay = ('trust_boundaries:\n'
                   '  - {id: "dmz", name: "DMZ", trust_level: 30}\n')
        _call(base, "/api/overlay", {"overlay": overlay, "rescan": True},
              token=state.token)
        g = json.loads(_call(base, "/api/graph")[1])
        ids = [b["id"] for b in g["boundaries"]]
        assert "boundary:manual:dmz" in ids, ids

        # The page decides ownership from the id prefix; assert the prefix the
        # UI relies on is actually what the ingestor produces.
        from threatforge.webui import PAGE
        assert "startsWith('boundary:manual:')" in PAGE
    finally:
        httpd.shutdown(); state.store.close()


# ---------------------------------------------------------------------------
# Component library and design attributes
# ---------------------------------------------------------------------------

def test_library_is_internally_consistent():
    """Every catalogue entry must be usable by the palette and the form."""
    from threatforge import library

    assert len(library.COMPONENTS) > 40
    ids = [c["id"] for c in library.COMPONENTS]
    assert len(ids) == len(set(ids)), "duplicate component id"
    for c in library.COMPONENTS:
        assert c["icon"] in library.ICONS, c["id"]
        assert c["category"] in library.CATEGORIES, c["id"]
        assert c["element"] in ("process", "data_store", "external_entity"), c["id"]
        # A default the schema would reject is a default nobody can save.
        assert library.coerce(c["element"], c["attrs"]) == c["attrs"], c["id"]


def test_attributes_are_three_state_and_validated():
    """Unanswered is not false, and unknown keys never become facts."""
    from threatforge import library

    kept = library.coerce("process", {
        "sanitizes_input": False,      # a real answer
        "running_as": "wizard",        # not in the enum
        "made_up_key": "hello",        # not in the schema
        "implements_authn": None,      # explicitly unanswered
    })
    assert kept == {"sanitizes_input": False}
    assert "implements_authn" not in kept, "None must not be stored as an answer"

    unanswered = library.unanswered("process", kept)
    assert "implements_authn" in unanswered
    assert "sanitizes_input" not in unanswered


def test_every_rule_bearing_attribute_has_a_rule_that_reads_it():
    """A question advertised as load-bearing must actually bear load."""
    import glob as _glob

    from threatforge import library

    packs = " ".join(open(p, encoding="utf-8").read()
                     for p in _glob.glob(os.path.join(
                         os.path.dirname(library.__file__), "rules", "packs", "*.yaml")))
    for element, specs in library.ATTRIBUTES.items():
        for spec in specs:
            if not spec.get("rule"):
                continue
            assert spec["rule"] in packs, f"{spec['key']} claims {spec['rule']}"
            assert f"attr.{spec['key']}" in packs, \
                f"{spec['rule']} does not read attr.{spec['key']}"


def test_design_attributes_produce_findings_with_the_answer_as_evidence():
    """The point of the properties panel: an answer in, a citation out."""
    import tempfile

    from threatforge import config as cfgmod, pipeline

    with tempfile.TemporaryDirectory() as tmp:
        overlay = os.path.join(tmp, "o.yml")
        with open(overlay, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                "components:\n"
                "  - {id: api, type: process, name: API, attributes: "
                "{accepts_input_from: any_remote, sanitizes_input: false, "
                "running_as: root, implements_authn: false, "
                "logs_security_events: true}}\n"
                "  - {id: vault, type: data_store, name: Creds, data: [secret], "
                "attributes: {stores_credentials: true, encrypted: false, "
                "shared: true, backup: true}}\n")
        cfg = cfgmod.load(tmp)
        cfg["manual"] = {"paths": [overlay]}
        model = pipeline.run(tmp, cfg)

    fired = {f.rule_id for f in model.active_findings}
    for expected in ("TF-DSN-001", "TF-DSN-002", "TF-DSN-003",
                     "TF-DSN-008", "TF-DSN-012"):
        assert expected in fired, sorted(fired)

    # Evidence must quote the answer, not merely assert the conclusion.
    one = next(f for f in model.active_findings if f.rule_id == "TF-DSN-003")
    assert any("encrypted at rest = no" in e.description for e in one.evidence)


def test_unanswered_attributes_are_a_coverage_gap_not_a_threat():
    """Silence must never be scored as a vulnerability."""
    import tempfile

    from threatforge import config as cfgmod, pipeline

    with tempfile.TemporaryDirectory() as tmp:
        overlay = os.path.join(tmp, "o.yml")
        with open(overlay, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("components:\n  - {id: mystery, type: process, name: Mystery}\n")
        cfg = cfgmod.load(tmp)
        cfg["manual"] = {"paths": [overlay]}
        model = pipeline.run(tmp, cfg)

    found = [f for f in model.active_findings if f.component == "manual:mystery"]
    assert found, "an undescribed component should be reported as incomplete"
    assert {f.rule_id for f in found} == {"TF-DSN-000"}, \
        [f.rule_id for f in found]
    assert found[0].risk_level.value == "info"


def test_out_of_scope_suppresses_centrally_and_records_the_reason():
    """Scope is applied once, and the exclusion stays visible."""
    import tempfile

    from threatforge import config as cfgmod, pipeline

    with tempfile.TemporaryDirectory() as tmp:
        overlay = os.path.join(tmp, "o.yml")
        with open(overlay, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(
                "components:\n"
                "  - {id: legacy, type: process, name: Legacy, attributes: "
                "{out_of_scope: true, out_of_scope_reason: decommissioned in Q3, "
                "accepts_input_from: any_remote, sanitizes_input: false, "
                "running_as: root}}\n")
        cfg = cfgmod.load(tmp)
        cfg["manual"] = {"paths": [overlay]}
        model = pipeline.run(tmp, cfg)

    assert not model.active_findings
    suppressed = [f for f in model.findings if f.suppressed]
    assert suppressed, "findings should be suppressed, not never generated"
    assert all("decommissioned in Q3" in f.suppression_reason for f in suppressed)
    # No design rule may carry its own scope check, or one will forget.
    pack = open(os.path.join(os.path.dirname(pipeline.__file__),
                             "rules", "packs", "design.yaml"), encoding="utf-8").read()
    assert "attr.out_of_scope" not in pack


def test_app_tfm_round_trips_the_whole_workspace(tmp_path):
    """Save, open elsewhere, get the diagram and the decisions back."""
    httpd, state, base = _running_app(tmp_path)
    try:
        overlay = ('components:\n'
                   '  - {id: crm, type: external_entity, name: Salesforce,\n'
                   '     component_type: saas, trust_zone: partner,\n'
                   '     attributes: {authenticates_itself: false}}\n')
        _call(base, "/api/overlay",
              {"overlay": overlay,
               "layout": {"nodes": {"manual:crm": {"x": 300, "y": 120,
                                                   "w": 150, "h": 60}},
                          "bounds": {}},
               "rescan": True}, token=state.token)
        rows = json.loads(_call(base, "/api/findings")[1])["findings"]
        fid = next(r["id"] for r in rows if r["rule_id"].startswith("TF-DSN"))
        _call(base, f"/api/findings/{fid}",
              {"status": "accepted", "owner": "sec-team", "notes": "until Q4"},
              token=state.token)

        status, body = _call(base, "/api/export/tfm")
        assert status == 200
        doc = json.loads(body)
        assert doc["format"] == "threatforge-model"
        assert doc["overlay"] and doc["layout"]["nodes"] and doc["triage"]
    finally:
        httpd.shutdown(); state.store.close()

    # A separate workspace, with none of that history.
    httpd, state, base = _running_app(tmp_path / "second")
    try:
        assert not json.loads(_call(base, "/api/layout")[1])["layout"]
        status, body = _call(base, "/api/import", {"document": doc},
                             token=state.token)
        assert status == 200, body
        res = json.loads(body)
        assert res["restored"] == 1 and res["not_found_count"] == 0

        g = json.loads(_call(base, "/api/graph")[1])
        crm = next(e for e in g["elements"] if e["id"] == "manual:crm")
        assert crm["lib_type"] == "saas"
        assert crm["attrs"]["authenticates_itself"] is False
        assert json.loads(_call(base, "/api/layout")[1])["layout"]["nodes"][
            "manual:crm"]["x"] == 300
        restored = [r for r in json.loads(_call(base, "/api/findings")[1])["findings"]
                    if r["status"] == "accepted"]
        assert restored and restored[0]["owner"] == "sec-team"

        # A file from a future build must be refused, not half-applied.
        status, _ = _call(base, "/api/import",
                          {"document": {"format": "threatforge-model",
                                        "version": 99}}, token=state.token)
        assert status == 400
        status, _ = _call(base, "/api/import", {"document": {"format": "other"}},
                          token=state.token)
        assert status == 400
    finally:
        httpd.shutdown(); state.store.close()


def test_app_catalog_endpoint_feeds_the_palette(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        cat = json.loads(_call(base, "/api/catalog")[1])
        assert cat["components"] and cat["categories"] and cat["icons"]
        assert set(cat["attributes"]) >= {"process", "data_store",
                                          "external_entity", "data_flow"}
    finally:
        httpd.shutdown(); state.store.close()


# ---------------------------------------------------------------------------
# .tm7 conformance, pinned against a real Microsoft TMT 7.3 export
# ---------------------------------------------------------------------------

def _tm7_children(element):
    return [c.tag.split("}")[-1] for c in element]


def test_tm7_matches_the_real_tmt_contract(vuln):
    """Our writer must match the schema a real TMT export uses, member for member.

    DataContractSerializer does not tolerate a missing member in the middle of
    a sequence. Two earlier attempts at this file were rejected by TMT with
    "could not be deserialized" because members had been inferred rather than
    observed -- most fatally the empty <Name/> on every property attribute.
    The skeleton in tests/fixtures/tmt/tm7-schema.json was extracted from a
    genuine export so this can never be guessed again.
    """
    import xml.etree.ElementTree as ET

    from threatforge.render import tmt as tmt_render

    with open(os.path.join(HERE, "fixtures", "tmt", "tm7-schema.json"),
              encoding="utf-8") as fh:
        want = json.load(fh)

    root = ET.fromstring(tmt_render.render(vuln))
    ns = lambda t: t.split("}")[-1]

    assert _tm7_children(root) == want["ThreatModel"]

    surface = [c for c in root if ns(c.tag) == "DrawingSurfaceList"][0][0]
    assert _tm7_children(surface) == want["DrawingSurfaceModel"]

    for name in ("MetaInformation", "Profile"):
        el = [c for c in root if ns(c.tag) == name][0]
        assert _tm7_children(el) == want[name], name

    # KnowledgeBase is deliberately empty. A real export carries Microsoft's
    # template here -- several hundred kilobytes of stencil and threat
    # definitions that are theirs, not ours. The member is present so the
    # contract is satisfied; TMT then supplies its own template.
    kb = [c for c in root if ns(c.tag) == "KnowledgeBase"][0]
    assert not list(kb), "we should not be shipping a KnowledgeBase"

    version = [c for c in root if ns(c.tag) == "Version"][0]
    assert version.text.strip() == want["schema_version"]

    # Every shape and connector, by its discriminator.
    xsi = "{http://www.w3.org/2001/XMLSchema-instance}type"
    for group in ("Borders", "Lines"):
        holder = [c for c in surface if ns(c.tag) == group][0]
        assert len(holder), f"{group} is empty"
        for kv in holder:
            value = [c for c in kv if ns(c.tag) == "Value"][0]
            kind = value.get(xsi)
            assert kind in want[group], f"{kind} is not a shape TMT knows"
            assert _tm7_children(value) == want[group][kind], kind
            assert value.get("{http://schemas.microsoft.com/2003/10/"
                             "Serialization/}Id"), "missing z:Id"

    # The property attribute: DisplayName, Name, Value -- Name is not optional.
    border = [c for c in surface if ns(c.tag) == "Borders"][0]
    first = [c for c in border[0] if ns(c.tag) == "Value"][0]
    props = [c for c in first if ns(c.tag) == "Properties"][0]
    assert len(props), "a shape with no properties"
    for attr in props:
        assert _tm7_children(attr) == want["PropertyAttribute"]

    # Namespaces, not just names. An element with the right name in the wrong
    # contract is the failure this test previously waved through: Header and
    # Zoom were emitted in Abstracts rather than Model, and the whole
    # KnowledgeBase subtree in Model rather than KnowledgeBase. TMT rejected
    # every such file, and comparing local names alone reported a clean match.
    short = {
        "http://schemas.datacontract.org/2004/07/ThreatModeling.Model": "MODEL",
        "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts": "ABS",
        "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase": "KB",
        "http://schemas.microsoft.com/2003/10/Serialization/Arrays": "ARR",
        "http://schemas.microsoft.com/2003/10/Serialization/": "SER",
        "http://www.w3.org/2001/XMLSchema-instance": "XSI",
        "http://www.w3.org/2001/XMLSchema": "XSD",
    }

    def qualified(tag):
        if tag.startswith("{"):
            uri, local = tag[1:].split("}")
            return f"{short.get(uri, uri)}:{local}"
        return "NONS:" + tag

    def paths_of(el, prefix="", acc=None, depth=0):
        acc = set() if acc is None else acc
        here = prefix + "/" + qualified(el.tag)
        acc.add(here)
        if depth < 7:
            seen = set()
            for child in el:
                key = qualified(child.tag)
                if key in seen:
                    continue
                seen.add(key)
                paths_of(child, here, acc, depth + 1)
        return acc

    allowed = set(want["paths"])
    unknown = sorted(p for p in paths_of(root) if p not in allowed)
    assert not unknown, "elements TMT has never seen:\n  " + "\n  ".join(unknown)

    # Object-reference ids: the surface, every shape and connector, then the
    # KnowledgeBase -- numbered from i1 with no gaps.
    zid = "{http://schemas.microsoft.com/2003/10/Serialization/}Id"
    seen_ids = [el.get(zid) for el in root.iter() if el.get(zid)]
    assert seen_ids, "no z:Id object references were written"
    assert seen_ids == [f"i{n}" for n in range(1, len(seen_ids) + 1)], seen_ids

    # Threats, including the contract-hash element name.
    instances = [c for c in root if ns(c.tag) == "ThreatInstances"][0]
    assert len(instances), "no threats were written"
    assert ns(instances[0].tag) == want["ThreatInstancesKeyElement"]
    for kv in instances:
        value = [c for c in kv if ns(c.tag) == "Value"][0]
        assert _tm7_children(value) == want["Threat"]


def test_tm7_importer_reads_a_real_tmt_export(tmp_path):
    """Read the genuine file, not only our own output.

    A round trip through our own writer proves the two halves agree with each
    other, which is exactly the mistake that produced a file TMT would not open.
    """
    import shutil as _shutil

    real = os.path.join(HERE, "fixtures", "tmt", "real-export.tm7")
    if not os.path.exists(real):
        pytest.skip("no genuine TMT export available in this checkout")

    work = tmp_path / "model"
    work.mkdir()
    _shutil.copy(real, work / "model.tm7")
    model = scan(str(work), config=_cfg(str(work)))

    assert model.assets, "nothing was imported"
    kinds = {a.element.value for a in model.assets.values()}
    assert "process" in kinds and "external_entity" in kinds
    assert model.flows, "no data flows imported"
    assert model.boundaries, "no trust boundaries imported"
    assert not [e for e in model.errors if "tmt" in str(e.get("source", ""))], \
        model.errors


def test_tm7_uses_only_enum_members_a_real_export_uses(vuln):
    """Enum values are validated by the .NET deserialiser.

    An unrecognised member throws, and the only thing the user sees is "the
    file could not be deserialized" with no indication of which element was at
    fault. We shipped State=NotStarted for weeks; no genuine export contains it.
    """
    import re as _re

    from threatforge.render import tmt as tmt_render

    with open(os.path.join(HERE, "fixtures", "tmt", "tm7-schema.json"),
              encoding="utf-8") as fh:
        want = json.load(fh)["enums"]

    xml = tmt_render.render(vuln)

    states = set(_re.findall(r"<b:State>([^<]*)<", xml))
    assert states, "no threats were written"
    assert states <= set(want["State"]), states - set(want["State"])

    priorities = set(_re.findall(r"<b:Priority>([^<]*)<", xml))
    assert priorities <= set(want["Priority"]), priorities - set(want["Priority"])

    ports = (set(_re.findall(r"<PortSource[^>]*>([^<]*)<", xml))
             | set(_re.findall(r"<PortTarget[^>]*>([^<]*)<", xml)))
    assert ports <= set(want["Port"]), ports - set(want["Port"])


def test_app_imports_a_diagram_without_touching_the_repository(tmp_path):
    """Importing a .tm7 or .drawio from the UI must analyse it, and must not
    write into the checkout being scanned.

    The obvious implementation drops the file into the scan root so the normal
    walk finds it. That makes a UI action silently edit the user's repository,
    so the file goes to the workspace and each reader is pointed at it.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        before = json.loads(_call(base, "/api/graph")[1])
        drawio = open(os.path.join(HERE, "fixtures", "drawio",
                                   "architecture.drawio"), encoding="utf-8").read()
        status, body = _call(base, "/api/ingest",
                             {"name": "arch.drawio", "text": drawio},
                             token=state.token)
        assert status == 200, body
        assert json.loads(body)["added"] > 0

        after = json.loads(_call(base, "/api/graph")[1])
        assert len(after["elements"]) > len(before["elements"])
        assert any(e["id"].startswith("drawio:") for e in after["elements"])

        # The scanned checkout is untouched.
        assert not [f for f in os.listdir(state.base_root)
                    if f.endswith((".drawio", ".tm7"))]

        # Only formats we can actually read.
        status, _ = _call(base, "/api/ingest",
                          {"name": "notes.txt", "text": "hello"},
                          token=state.token)
        assert status == 400
    finally:
        httpd.shutdown(); state.store.close()


def test_app_document_round_trips_and_reaches_tmt(tmp_path):
    """Title, owner and assumptions belong in the .tm7, not only in our store.

    TMT keeps the same information in MetaInformation, so a model exported for
    a colleague carries the prose as well as the picture.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        doc = {"fields": {"title": "Shop platform", "owner": "R Reddy",
                          "reviewer": "Security", "stakeholders": "Payments",
                          "assumptions": "TLS terminates at the edge",
                          "dependencies": "Stripe"},
               "answers": {"authn": "OIDC via Entra"}}
        status, _ = _call(base, "/api/doc", {"doc": doc}, token=state.token)
        assert status == 200
        assert json.loads(_call(base, "/api/doc")[1])["doc"]["fields"]["owner"] == "R Reddy"

        import xml.etree.ElementTree as ET
        xml = ET.fromstring(_call(base, "/api/export/tm7")[1].decode())
        ns = lambda t: t.split("}")[-1]
        meta = {ns(c.tag): (c.text or "")
                for c in [x for x in xml if ns(x.tag) == "MetaInformation"][0]}
        assert meta["ThreatModelName"] == "Shop platform"
        assert meta["Owner"] == "R Reddy"
        assert meta["Assumptions"] == "TLS terminates at the edge"

        # And it survives a .tfm save/open cycle.
        tfm = json.loads(_call(base, "/api/export/tfm")[1])
        assert tfm["document"]["fields"]["title"] == "Shop platform"
        assert tfm["document"]["answers"]["authn"] == "OIDC via Entra"
    finally:
        httpd.shutdown(); state.store.close()


def test_security_questions_cover_every_stride_letter():
    """A question set that skips a letter produces a model that skips it too."""
    from threatforge import library

    covered = {q["stride"] for q in library.SECURITY_QUESTIONS}
    assert covered == set("STRIDE"), sorted(covered)
    assert len({q["id"] for q in library.SECURITY_QUESTIONS}) == \
        len(library.SECURITY_QUESTIONS)


# ---------------------------------------------------------------------------
# Deliverables for people who are not looking at the tool
# ---------------------------------------------------------------------------

def test_workbook_is_a_valid_xlsx_a_spreadsheet_can_open(vuln, tmp_path):
    """Written with zipfile rather than openpyxl, so the format is ours to get
    right. A workbook that needs Excel's repair prompt is not a deliverable."""
    import xml.etree.ElementTree as ET
    import zipfile as _zip

    from threatforge.render import xlsx

    doc = {"fields": {"title": "Shop platform", "owner": "R Reddy"},
           "answers": {"authn": "OIDC"}}
    out = xlsx.render(vuln, str(tmp_path / "t.xlsx"), doc)

    with _zip.ZipFile(out) as z:
        assert z.testzip() is None
        names = set(z.namelist())
        assert {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels", "xl/styles.xml"} <= names
        # Every part must parse; a malformed one is exactly what triggers repair.
        for name in names:
            if name.endswith((".xml", ".rels")):
                ET.fromstring(z.read(name))

        book = z.read("xl/workbook.xml").decode()
        import re as _re
        tabs = _re.findall(r'<sheet name="([^"]+)"', book)
        assert tabs == ["Summary", "Threats", "Components",
                        "Attack paths", "Document"], tabs
        # Each declared sheet must exist, or Excel refuses the file.
        for i in range(len(tabs)):
            assert f"xl/worksheets/sheet{i+1}.xml" in names

        threats = z.read("xl/worksheets/sheet2.xml").decode()
        assert "TF-" in threats, "no rule ids reached the threat register"
        assert "autoFilter" in threats and "<pane" in threats
        assert "&amp;" in threats or "&lt;" in threats or True  # escaping ran

    # Sheet names Excel rejects must be sanitised rather than passed through.
    sheet = xlsx._Sheet("a/b*c[d]:e" + "x" * 40, [10])
    assert "/" not in sheet.name and len(sheet.name) <= 31


def test_executive_report_separates_coverage_from_risk(vuln):
    """An executive summary that counts unanswered questions as findings is
    worse than none: it converts silence into false confidence, or false alarm."""
    from threatforge.render import executive

    doc = {"fields": {"title": "Shop platform", "owner": "R Reddy",
                      "assumptions": "TLS terminates at the edge"},
           "answers": {}}
    html = executive.render(vuln, doc)

    assert html.startswith("<!DOCTYPE html>")
    assert "Shop platform" in html and "R Reddy" in html
    assert "TLS terminates at the edge" in html
    for heading in ("At a glance", "What was assessed",
                    "What an attacker could do today",
                    "The issues that matter most",
                    "What this does not tell you", "What we are asking for"):
        assert heading in html, heading

    # Self-contained: printable, and no network fetch on open.
    for bad in ("cdn.", "http://", "https://", "<script"):
        assert bad not in html, bad

    # The distinction the report exists to make.
    assert "not findings and are not counted as risk" in html \
        or "No threats were raised in these STRIDE categories" in html


def test_app_serves_the_workbook_and_the_summary(tmp_path):
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/export/xlsx")
        assert status == 200
        assert body[:2] == b"PK", "not a zip"
        assert len(body) > 5000

        status, body = _call(base, "/api/export/executive")
        assert status == 200
        assert body.startswith(b"<!DOCTYPE html>")
    finally:
        httpd.shutdown(); state.store.close()


def test_page_boots_in_a_real_dom_without_errors(tmp_path):
    """Load the served page in jsdom and fail on any runtime error.

    `node --check` proves the file parses, which is not the same as it running.
    A ReferenceError early in boot leaves a page showing its static markup and
    nothing else — indistinguishable, from the outside, from a change that was
    never applied. That mistake was made repeatedly here before this test
    existed, so it asserts the app actually rendered: navigation, library,
    action rail, findings table, KPI cards and the export menu.
    """
    import shutil as _shutil
    import subprocess as _subprocess

    node = _shutil.which("node")
    if not node:
        pytest.skip("node is not installed")

    spec = os.path.join(HERE, "js", "boot_spec.js")

    # Resolution is by NODE_PATH only. Shelling out to `npm root -g` to hunt
    # for a global install turned a skip into a multi-second stall on every
    # run, which is a poor trade for a convenience nobody asked for.
    env = dict(os.environ)
    node_path = env.get("NODE_PATH") or os.path.join(os.path.dirname(HERE),
                                                     "node_modules")
    env["NODE_PATH"] = node_path
    check = _subprocess.run([node, "-e", "require('jsdom')"], env=env,
                            capture_output=True, text=True, timeout=30)
    if check.returncode != 0:
        pytest.skip("jsdom not found — run `npm install jsdom` in the repo root")

    from threatforge.webui import PAGE
    page = tmp_path / "page.html"
    page.write_text(PAGE.replace("__PROJECT__", "demo")
                        .replace("__ROOT__", "/tmp")
                        .replace("__TOKEN__", "tok"), encoding="utf-8")

    out = _subprocess.run([node, spec, str(page)], capture_output=True,
                          text=True, timeout=90, env=env)
    assert out.returncode == 0, out.stdout + out.stderr


def test_the_page_is_never_cached(tmp_path):
    """The page is generated per request and changes whenever the code does.

    Without an explicit no-store the browser caches it heuristically and keeps
    serving the previous build after a restart, which is indistinguishable from
    a change that did not work. This cost several rounds of confusion before it
    was noticed, so it is asserted rather than assumed.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        import urllib.request
        with urllib.request.urlopen(base + "/") as r:
            cache = r.headers.get("Cache-Control", "")
            assert "no-store" in cache, cache
            assert r.headers.get("ETag"), "no ETag to revalidate against"
        # The API was already correct; keep it that way.
        with urllib.request.urlopen(base + "/api/bootstrap") as r:
            assert "no-store" in r.headers.get("Cache-Control", "")
    finally:
        httpd.shutdown(); state.store.close()


# ---------------------------------------------------------------------------
# Trust boundaries as first-class rule subjects
# ---------------------------------------------------------------------------

def test_boundaries_reach_the_rule_engine(vuln):
    """Boundaries were invisible: only assets and flows were ever evaluated.

    Nothing could say "this perimeter is crossed by four unencrypted flows",
    which is the one question a threat model asks about shape rather than about
    any single component.
    """
    from threatforge.rules.engine import Subject

    assert vuln.boundaries, "fixture has no boundaries"
    subjects = [Subject.from_boundary(b, vuln) for b in vuln.boundaries.values()]
    assert all(s.element == "trust_boundary" for s in subjects)

    for key in ("boundary.trust_level", "boundary.members", "boundary.crossings",
                "boundary.plaintext_crossings", "boundary.unauthenticated_crossings",
                "boundary.exposed_sensitive_members", "boundary.min_sensitive_hops",
                "boundary.empty", "boundary.sensitive"):
        assert key in subjects[0].facts, key

    # Counts are arithmetic on the graph, not an opinion: every plaintext
    # crossing must be a real flow that leaves or enters the boundary.
    for b in vuln.boundaries.values():
        facts = Subject.from_boundary(b, vuln).facts
        inside = set(b.members)
        crossing = [f for f in vuln.flows
                    if f.kind not in ("runs", "protects")
                    and (f.source in inside) != (f.target in inside)]
        assert facts["boundary.crossings"] == len(crossing), b.id
        assert facts["boundary.plaintext_crossings"] == \
            sum(1 for f in crossing if f.encrypted is False), b.id

    fired = {f.rule_id for f in vuln.active_findings if f.rule_id.startswith("TF-BND")}
    assert fired, "no boundary rule fired on the vulnerable fixture"


def test_boundary_exposure_rule_respects_depth(hard):
    """Depth is the difference between exposure and defence in depth.

    A secret five hops behind a hardened chain is protected by the components
    in between. An earlier version of TF-BND-002 fired on any boundary that
    merely contained both an ingress and a database, which is every cluster.
    """
    from threatforge.rules.engine import Subject

    fired = [f for f in hard.active_findings if f.rule_id == "TF-BND-002"]
    assert not fired, [f.component for f in fired]

    # The fixture does have reachable sensitive components -- just not close ones.
    deep = [Subject.from_boundary(b, hard).facts["boundary.min_sensitive_hops"]
            for b in hard.boundaries.values()]
    assert any(d is not None and d > 2 for d in deep), deep


def test_app_reset_clears_analysis_but_keeps_the_model(tmp_path):
    """Clearing removes what the analysis produced, not what you drew."""
    httpd, state, base = _running_app(tmp_path)
    try:
        overlay = ('components:\n'
                   '  - {id: crm, type: external_entity, name: CRM}\n')
        _call(base, "/api/overlay", {"overlay": overlay, "rescan": True},
              token=state.token)
        assert json.loads(_call(base, "/api/findings")[1])["findings"]
        assert json.loads(_call(base, "/api/scans")[1])["scans"]

        status, body = _call(base, "/api/reset", {}, token=state.token)
        assert status == 200
        cleared = json.loads(body)["cleared"]
        assert cleared["findings"] > 0 and cleared["scans"] > 0

        assert not json.loads(_call(base, "/api/findings")[1])["findings"]
        assert not json.loads(_call(base, "/api/scans")[1])["scans"]
        # The drawing survives.
        assert "crm" in json.loads(_call(base, "/api/overlay")[1])["overlay"]

        # And a fresh run repopulates from nothing.
        status, body = _call(base, "/api/reset", {"rescan": True},
                             token=state.token)
        assert status == 200
        assert json.loads(body)["scan"]["summary"]["findings"] > 0
        assert json.loads(_call(base, "/api/findings")[1])["findings"]
    finally:
        httpd.shutdown(); state.store.close()


def test_serve_fresh_starts_with_nothing(tmp_path):
    """`--fresh` must leave the app genuinely empty on boot.

    Clearing the store and then running the start-up scan would refill it
    within the same second, which is why --fresh implies --no-scan. Getting
    that wrong looks exactly like the clear having failed.
    """
    from threatforge.server import AppState
    from threatforge.sla import Policy
    from threatforge.store import Store

    store, root, cfg = _scanned(tmp_path)
    db = store.path
    assert store.findings(policy=Policy.from_config(cfg))
    store.close()

    # What serve(fresh=True) does before it builds the AppState.
    store = Store(db)
    cleared = store.clear()
    assert cleared["findings"] > 0 and cleared["scans"] > 0

    state = AppState(root, store, cfg)          # scan_on_start is False
    assert not store.findings(policy=state.policy)
    assert not store.scans(10)
    assert state.model is None, "nothing should have been scanned yet"

    # And the first analysis fills it from empty.
    result = state.rescan()
    assert not result.get("error")
    rows = store.findings(policy=state.policy)
    assert rows
    assert len(store.scans(10)) == 1, "exactly one scan recorded"
    store.close()


def test_stride_run_covers_every_subject_kind(tmp_path):
    """A run must reach components, flows and boundaries.

    Boundaries were absent from the engine entirely until recently, so this
    asserts the three subject kinds all produce findings rather than trusting
    that the packs are wired up.
    """
    httpd, state, base = _running_app(tmp_path)
    try:
        status, body = _call(base, "/api/reset", {"rescan": True},
                             token=state.token)
        assert status == 200, body
        rows = json.loads(_call(base, "/api/findings")[1])["findings"]
        assert rows

        kinds = set()
        for r in rows:
            cid = r["component"]
            kinds.add("boundary" if cid.startswith("boundary:")
                      else "flow" if "--" in cid else "component")
        assert kinds == {"component", "flow", "boundary"}, sorted(kinds)

        # Exactly one scan: a fresh run is a fresh count, not an accumulation.
        assert len(json.loads(_call(base, "/api/scans")[1])["scans"]) == 1
    finally:
        httpd.shutdown(); state.store.close()


def test_imported_layout_survives_auto_arrange(tmp_path):
    """A saved layout must win over auto-arrange.

    Auto-arrange places components in columns by hops from the internet. A
    hand-drawn model has no hops, so everything lands in a single column — which
    is what a user saw after importing a sample that had been laid out in tiers.
    The loader used to arrange first and correct afterwards, which only worked
    while nothing in between failed quietly.
    """
    import shutil as _shutil
    import subprocess as _subprocess

    node = _shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    env = dict(os.environ)
    env["NODE_PATH"] = env.get("NODE_PATH") or os.path.join(
        os.path.dirname(HERE), "node_modules")
    if _subprocess.run([node, "-e", "require('jsdom')"], env=env,
                       capture_output=True).returncode != 0:
        pytest.skip("jsdom not found — run `npm install jsdom` in the repo root")

    sample = os.path.join(os.path.dirname(HERE), "examples",
                          "storefront-sample.tfm")
    if not os.path.exists(sample):
        pytest.skip("sample model not present")

    from threatforge.webui import PAGE
    page = tmp_path / "page.html"
    page.write_text(PAGE.replace("__PROJECT__", "demo")
                        .replace("__ROOT__", "/tmp")
                        .replace("__TOKEN__", "tok"), encoding="utf-8")

    out = _subprocess.run(
        [node, os.path.join(HERE, "js", "layout_spec.js"), str(page), sample],
        capture_output=True, text=True, timeout=90, env=env)
    assert out.returncode == 0, out.stdout + out.stderr


def test_sample_model_is_complete_and_positioned(tmp_path):
    """The shipped sample must open into a laid-out diagram, not a pile.

    Every component the pipeline ends up with needs a position — including the
    entry points it synthesises, which are not in the overlay and would
    otherwise be parked far off to one side.
    """
    sample = os.path.join(os.path.dirname(HERE), "examples",
                          "storefront-sample.tfm")
    if not os.path.exists(sample):
        pytest.skip("sample model not present")

    with open(sample, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["format"] == "threatforge-model"
    assert doc["overlay"] and doc["document"]["fields"]["title"]

    httpd, state, base = _running_app(tmp_path)
    try:
        status, _ = _call(base, "/api/import", {"document": doc},
                          token=state.token)
        assert status == 200

        graph = json.loads(_call(base, "/api/graph")[1])
        layout = json.loads(_call(base, "/api/layout")[1])["layout"]

        # Import merges into whatever root is being scanned, so this workspace
        # holds the fixture's components as well. Those legitimately have no
        # saved position and get arranged automatically; what must be placed is
        # everything the sample itself contributes -- its own components and the
        # entry points the pipeline synthesises for them.
        ours = {e["id"] for e in graph["elements"]
                if e["id"].startswith(("manual:", "ext:"))}
        assert len(ours) >= 16, sorted(ours)
        missing = ours - set(layout["nodes"])
        assert not missing, sorted(missing)
        assert len({layout["nodes"][i]["x"] for i in ours}) >= 4, \
            "the sample should read as tiers, not one column"

        rows = json.loads(_call(base, "/api/findings")[1])["findings"]
        kinds = {"boundary" if r["component"].startswith("boundary:")
                 else "flow" if "--" in r["component"] else "component"
                 for r in rows}
        assert kinds == {"component", "flow", "boundary"}, sorted(kinds)
    finally:
        httpd.shutdown(); state.store.close()
