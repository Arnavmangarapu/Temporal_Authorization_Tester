"""A known static bug only counts when identity, rights and exact data agree."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from temporal_auth.integrations.dolibarr import LIST_PATH, REVISIONS, STEPS, analyze_static
from temporal_auth.evaluation import dolibarr_reproduction as campaign


MARKER = "TAT-protected-currency-pair-1"
STATE = {"currency_id": 2, "code": "XTS", "actors": {
    role: {"id": i, "login": role, "admin": int(role == "owner"), "currency_read": role != "restricted"}
    for i, role in enumerate(("owner", "allowed", "restricted"), 1)}}


def trace(discloses):
    record = {"id": "2", "code": "XTS", "name": MARKER}
    events = []
    for i, step in enumerate(STEPS):
        path, status, body = LIST_PATH, 200, [record]
        if step.startswith("identity_"):
            role = step.removeprefix("identity_")
            path = f"/api/index.php/users/{STATE['actors'][role]['id']}?includepermissions=1"
            body = {**STATE["actors"][role], "rights": {"multicurrency": {"currency": {"read": int(role != "restricted")}}}}
        elif step in ("anonymous", "invalid_key", "restricted_bycode") or (step == "restricted_list" and not discloses):
            status, body = 401, {"error": {"message": "Insufficient rights"}}
            if step == "restricted_bycode": path = "/api/index.php/multicurrencies/bycode/XTS"
        events.append({"sequence": i + 1, "step": step, "method": "GET", "path": path,
            "status": status, "body": json.dumps(body), "started": i * 2, "finished": i * 2 + 1,
            "error": None, "truncated": False})
    return events


@pytest.mark.parametrize("discloses,expected", [(True, "protected_data_disclosed"), (False, "access_denied")])
def test_bug_and_fix_with_full_positive_negative_identity_rights_controls(discloses, expected):
    assert analyze_static(trace(discloses), marker=MARKER, state=STATE)["verdict"] == expected


@pytest.mark.parametrize("mutation", ["admin_subject", "subject_has_right", "wrong_identity", "bad_owner", "bad_allowed",
    "missing", "duplicate", "truncated", "network", "wrong_record", "wrong_code", "wrong_path", "time", "extra_write"])
def test_misconfigured_or_corrupt_observations_never_prove_bug_or_fix(mutation):
    events = trace(True)
    if mutation in ("admin_subject", "subject_has_right", "wrong_identity"):
        data = json.loads(events[2]["body"])
        if mutation == "admin_subject": data["admin"] = 1
        elif mutation == "subject_has_right": data["rights"]["multicurrency"]["currency"]["read"] = 1
        else: data["id"] = "1"
        events[2]["body"] = json.dumps(data)
    elif mutation == "bad_owner": events[5]["status"] = 401
    elif mutation == "bad_allowed": events[-1]["body"] = "[]"
    elif mutation == "missing": events.pop(3)
    elif mutation == "duplicate": events.append(deepcopy(events[8]))
    elif mutation == "truncated": events[8]["truncated"] = True
    elif mutation == "network": events[8]["error"] = "timeout"
    elif mutation in ("wrong_record", "wrong_code"):
        data = json.loads(events[8]["body"]); data[0]["id" if mutation == "wrong_record" else "code"] = "different"
        events[8]["body"] = json.dumps(data)
    elif mutation == "wrong_path": events[8]["path"] = "/api/elsewhere"
    elif mutation == "time": events[-1]["started"] = 0
    else: events.insert(8, {**events[7], "step": "grant_access", "method": "POST"})
    assert analyze_static(events, marker=MARKER, state=STATE)["verdict"] == "inconclusive"


@pytest.mark.parametrize("status,body,expected", [(200, "[]", "inconclusive"),
    (500, '{"error":"broken"}', "inconclusive"), (403, '{"error":"denied"}', "access_denied")])
def test_status_alone_is_insufficient_and_denial_accepts_401_or_403(status, body, expected):
    events = trace(False); events[8].update(status=status, body=body)
    assert analyze_static(events, marker=MARKER, state=STATE)["verdict"] == expected


def test_frozen_protocol_includes_templates_and_rejects_source_edits(tmp_path, monkeypatch):
    root = tmp_path / "source"; template = root / "integrations/dolibarr/conf.php"
    template.parent.mkdir(parents=True); template.write_text("fixture")
    build = root / "artifacts/tools/dolibarr-26066/build.json"; build.parent.mkdir(parents=True)
    build.write_text(json.dumps({"fixture_sha256": {"integrations/dolibarr/conf.php": campaign.digest(template)},
        "source_lock": {}, "images": {}, "source_difference_verified": ["handler.php"]}))
    monkeypatch.setattr(campaign, "inventory", lambda root: {"integrations/dolibarr/conf.php": campaign.digest(template)})
    path = tmp_path / "protocol.json"; protocol = campaign.freeze(root, path)
    assert campaign.load_protocol(path, root) == protocol
    assert len(set(campaign.work_items(protocol))) == 6
    with pytest.raises(ValueError): campaign.freeze(root, path)
    template.write_text("modified")
    with pytest.raises(ValueError, match="Source/environment"): campaign.load_protocol(path, root)
    with pytest.raises(ValueError, match="Rebuild"): campaign.freeze(root, tmp_path / "new.json")


def test_campaign_retains_failures_resumes_and_detects_evidence_edits(tmp_path, monkeypatch):
    protocol = {"pairs": [1], "revisions": REVISIONS, "order_seed": 1, "protocol_sha256": "freeze",
        "expected": {"buggy": "protected_data_disclosed", "fixed": "access_denied"},
        "max_requests": 100, "max_seconds": 300, "images": {v: {"id": v} for v in REVISIONS}}
    calls = []
    def runner(variant, base, **kwargs):
        base.mkdir(parents=True); calls.append(variant)
        report = {"variant": variant, "revision": REVISIONS[variant], "status": "execution_error",
                  "verdict": "inconclusive", "requests": 0, "elapsed_seconds": 1}
        (base / "reproduction.json").write_text(json.dumps(report)); return report, base
    monkeypatch.setattr(campaign, "run_reproduction", runner)
    campaign.run(protocol, tmp_path); campaign.run(protocol, tmp_path)
    assert len(calls) == 2
    result = campaign.analyze(protocol, tmp_path)
    assert result["all_rows_recorded"] and result["reproduced_pairs"] == 0
    assert result["population_recall"] is None and not result["temporal_claim"]
    row = campaign.read_rows(tmp_path, protocol)[0]
    (tmp_path / row["directory"] / "reproduction.json").write_text("modified")
    with pytest.raises(ValueError, match="evidence changed"): campaign.read_rows(tmp_path, protocol)


def test_offline_analysis_recomputes_oracle_instead_of_trusting_summary(tmp_path):
    protocol = {"pairs": [1], "revisions": REVISIONS, "order_seed": 1, "protocol_sha256": "freeze"}
    run = tmp_path / "run"; run.mkdir()
    report = {"variant": "buggy", "revision": REVISIONS["buggy"], "status": "completed",
              "marker": MARKER, "fixture": {"state": STATE}, "verdict": "access_denied",
              "analysis": {"verdict": "access_denied", "reason": "wrong"}}
    (run / "reproduction.json").write_text(json.dumps(report))
    (run / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in trace(True)))
    row = {"key": ["buggy", 1], "protocol_sha256": "freeze", "directory": "run", "report": report,
           "evidence_sha256": campaign.evidence_index(run)}
    row["row_sha256"] = campaign.canonical_digest(row)
    (tmp_path / "rows.jsonl").write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="oracle result"): campaign.read_rows(tmp_path, protocol)
