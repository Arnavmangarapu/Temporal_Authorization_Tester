"""Evaluation provenance, ground truth and analysis units are executable checks."""

import asyncio
from copy import deepcopy
import json
from pathlib import Path

import httpx
import pytest

from temporal_auth.evaluation.analysis import analyze, method_summary
from temporal_auth.evaluation.campaign import load_rows, row_digest, run_campaign, work_items
from temporal_auth.evaluation.controlled import LogicalClock, configuration, run_controlled, run_early, scenario, target
from temporal_auth.evaluation.protocol import METHODS, canonical_digest, corpus, freeze, load_protocol

ROOT = Path(__file__).resolve().parents[1]
BUDGET = {"max_requests": 500, "max_runtime_seconds": 600.0}


def case(identifier):
    return next(c for c in corpus() if c["id"] == identifier)


def test_corpus_truth_and_deduplication_units():
    cases = corpus()
    assert len(cases) == 29 and len({c["id"] for c in cases}) == 29
    assert sum(c["truth"] == "violation" for c in cases) == 10
    assert sum(c["truth"] == "correct" for c in cases) == 16
    assert sum(c["truth"] == "inconclusive" for c in cases) == 3
    assert {c["root_cause"] for c in cases if c["truth"] == "violation"} == {"stale_snapshot", "commit_before_denial"}


def test_freeze_is_immutable_and_detects_protocol_and_source_changes(tmp_path):
    path = tmp_path / "protocol.json"
    frozen = freeze(ROOT, path)
    assert load_protocol(path, ROOT) == frozen
    with pytest.raises(ValueError, match="already exists"): freeze(ROOT, path)
    bad = deepcopy(frozen); bad["seeds"] = [1]; path.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="hash mismatch"): load_protocol(path, ROOT)
    bad = deepcopy(frozen); bad["source_sha256"]["pyproject.toml"] = "0" * 64
    bad["protocol_sha256"] = canonical_digest({k: v for k, v in bad.items() if k != "protocol_sha256"})
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError, match="Source changed"): load_protocol(path, ROOT)


@pytest.mark.parametrize("method", METHODS)
def test_schedulers_preserve_causal_evidence_contracts(method):
    cfg = configuration(ROOT, case("role-write-stale_session"), BUDGET)
    plan = scenario(cfg, method, 1000)
    plan.validate_for(cfg)
    assert {n.id for n in plan.nodes} >= {"transition", "wait_for_deadline", "probe_old", "probe_fresh", "readback_old", "readback_fresh"}
    assert len(plan.nodes) == (19 if method == "seeded-minimal" else 21)
    if method == "canonical-dag":
        assert [n.id for n in plan.nodes] == [n.id for n in scenario(cfg, method, 1001).nodes]


@pytest.mark.parametrize("overlay,old_status,old_discloses,control_status", [
    ("disclosure_403", 403, True, 200), ("public_metadata_200", 200, False, 200), ("control_failure", 403, False, 503)])
def test_overlay_ground_truth_through_independent_manual_api_flow(overlay, old_status, old_discloses, control_status):
    async def execute():
        selected = case("sharing-read-" + overlay); clock = LogicalClock()
        async with target(selected, clock) as factory:
            async with httpx.AsyncClient(base_url="http://lab", transport=factory()) as client:
                async def login(name):
                    r = await client.post("/auth/login", json={"username": name, "password": name + "-demo-password"})
                    return r.json()
                owner = await login("alice"); subject = await login("bob")
                h = {"Authorization": "Bearer " + owner["access_token"]}
                created = await client.post("/documents", headers=h, json={"content": "ground-truth-marker"})
                identifier = created.json()["id"]
                await client.post(f"/documents/{identifier}/shares", headers=h, json={"subject_id": subject["user_id"]})
                old = await login("bob")
                revoked = await client.delete(f"/documents/{identifier}/shares/{subject['user_id']}", headers=h)
                assert revoked.status_code == 200
                await clock.sleep(6)
                r = await client.get(f"/documents/{identifier}", headers={"Authorization": "Bearer " + old["access_token"]})
                assert r.status_code == old_status
                assert ("ground-truth-marker" in r.text) == old_discloses
                r = await client.get(f"/documents/{identifier}", headers=h)
                assert r.status_code == control_status
    asyncio.run(execute())


@pytest.mark.parametrize("identifier,expected", [
    ("sharing-read-disclosure_403", "confirmed_violation"), ("sharing-read-public_metadata_200", "no_violation_observed"),
    ("sharing-read-control_failure", "inconclusive"), ("sharing-read-unknown_policy", "inconclusive"),
    ("sharing-read-unavailable", "inconclusive"), ("role-write-write_side_effect", "confirmed_violation")])
def test_controlled_checker_and_retrospective_scope(tmp_path, identifier, expected):
    row = asyncio.run(run_controlled(ROOT, case(identifier), "seeded-dag", 1000, BUDGET, tmp_path))
    assert row["verdict"] == expected
    if identifier.endswith("unknown_policy"): assert row["requests"] == 0
    if identifier.endswith("unavailable"): assert row["requests"] == 1 and row["status"] == "execution_error"
    if identifier.endswith("public_metadata_200"):
        assert row["posthoc"]["status-only"]["verdict"] == "candidate"
        assert row["posthoc"]["status-only"]["observed_attempts"] == 1
    if identifier.endswith("write_side_effect"):
        assert row["posthoc"]["status-only"]["verdict"] == "no_violation_observed"
    if identifier.endswith("disclosure_403"):
        assert row["posthoc"]["fresh-only"]["verdict"] == "no_violation_observed"


@pytest.mark.parametrize("action", ["read", "write"])
def test_early_probe_is_an_unsafe_claim_on_correct_delayed_fixture(tmp_path, action):
    row = asyncio.run(run_early(ROOT, case(f"sharing-{action}-delayed"), 1000, BUDGET, tmp_path))
    assert row["verdict"] == "inconclusive" and row["reason"] == "probe_before_deadline"
    assert row["unsafe_early_claim"] == "candidate" and row["confirmation"] == "not_attempted"


def small_protocol(tmp_path):
    p = freeze(ROOT, tmp_path / "frozen.json")
    # A separately labeled small unit-test protocol, never the canonical study.
    p["tracks"]["logical"].update(cases=["sharing-read-immediate"], methods=["seeded-dag"], seeds=[1000])
    p["protocol_sha256"] = canonical_digest({k: v for k, v in p.items() if k != "protocol_sha256"})
    return p


def test_resume_does_not_double_count_and_missing_rows_remain_visible(tmp_path):
    p = small_protocol(tmp_path); output = tmp_path / "campaign"
    for _ in range(2): asyncio.run(run_campaign(ROOT, p, output, track="logical", progress=lambda *args, **kwargs: None))
    rows = load_rows(output, p); assert len(rows) == 1
    report = analyze(p, output)
    assert report["coverage"]["logical"] == {"required": 1, "recorded": 1}
    assert report["all_frozen_rows_recorded"] is False
    assert report["controlled"]["seeded-dag"]["correct_configurations"]["denominator"] == 1
    assert report["research_readiness"]["held_out_defect_families"] is False
    file = next((output / rows[0]["evidence"]).rglob("run.json")); file.write_text("{}")
    with pytest.raises(ValueError, match="Evidence changed"): load_rows(output, p)


def test_repeated_seeds_do_not_become_independent_defects(tmp_path):
    selected = case("sharing-read-stale_session")
    row = asyncio.run(run_controlled(ROOT, selected, "seeded-dag", 1000, BUDGET, tmp_path))
    rows = [{"case": selected["id"], "observed": row} for _ in range(10)]
    summary = method_summary(rows, {selected["id"]: selected})
    assert summary["runs"] == 10 and summary["defect_configurations"]["denominator"] == 1
    assert summary["root_cause_families_detected"] == ["stale_snapshot"]


def test_workload_schedule_is_reproducible_and_unique(tmp_path):
    p = small_protocol(tmp_path)
    a = work_items(p, "external"); b = work_items(p, "external")
    assert a == b and len(a) == 60 and len({i["key"] for i in a}) == 60


def test_torn_rows_and_changed_row_metadata_are_rejected(tmp_path):
    p = small_protocol(tmp_path); output = tmp_path / "campaign"
    asyncio.run(run_campaign(ROOT, p, output, track="logical", progress=lambda *args, **kwargs: None))
    path = output / "rows.jsonl"; row = json.loads(path.read_text())
    row["observed"]["verdict"] = "confirmed_violation"; path.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="row changed"): load_rows(output, p)
    path.write_text('{"unfinished":')
    with pytest.raises(ValueError): load_rows(output, p)
