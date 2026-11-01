"""Shared-input pilot must distinguish coverage, controls, signals and provenance."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from temporal_auth.integrations import matched
from temporal_auth.evaluation import native_comparison as campaign


ROOT = Path(__file__).resolve().parents[1]


class Adapter:
    path = "/api/protected"
    marker = "protected-marker"
    owner = {"Authorization": "owner"}

    def __init__(self, native_status=403, native_body="denied", native=True):
        self.recorder = SimpleNamespace(events=[])
        for i, (step, method, status, body) in enumerate([
            ("read_before", "GET", 200, self.marker), ("control_before", "GET", 200, self.marker),
            ("transition", "PATCH", 200, "viewer"), ("transition_control", "GET", 200, "viewer")]):
            self.add(step, method, status, body, i * 2)
        if native: self.add("native_subject_get", "GET", native_status, native_body, 10)

    def add(self, step, method, status, body, started):
        self.recorder.events.append({"sequence": len(self.recorder.events) + 1, "step": step,
            "method": method, "path": self.path if "transition" not in step else "/api/roles",
            "status": status, "body": body, "started": started, "finished": started + 1,
            "error": None, "truncated": False})

    def read(self, step, session):
        owner = session == self.owner
        self.add(step, "GET", 200 if owner else 403, self.marker if owner else "denied",
                 20 + len(self.recorder.events) * 2)


def finish(adapter):
    return matched.finish(adapter, {"old": {"Authorization": "old"}, "fresh": {"Authorization": "fresh"}},
                          {"not_before_seconds": 5.05})


@pytest.mark.parametrize("status", [200, 403, 500])
def test_native_trace_content_signal_is_not_status_or_native_fault_label(status):
    result = finish(Adapter(status, "protected-marker"))
    assert result["native_trace_content_verdict"] == "candidate"
    assert result["protected_content_sequences"] == [5]
    assert not result["native_fault_labels_evaluated"]
    assert not result["clean_confirmation_performed"]


def test_public_metadata_and_absent_subject_probe_are_distinct():
    assert finish(Adapter(200, '{"public":true}'))["native_trace_content_verdict"] == "no_violation_observed"
    assert finish(Adapter(native=False))["native_trace_content_verdict"] == "not_exercised"


@pytest.mark.parametrize("mutation", ["early", "truncated", "network", "control", "ambiguous500"])
def test_invalid_native_observations_cannot_become_clean_nonfindings(mutation):
    adapter = Adapter()
    native = adapter.recorder.events[-1]
    if mutation == "early": native["started"] = 5
    elif mutation == "truncated": native["truncated"] = True
    elif mutation == "network": native["error"] = "timeout"
    elif mutation == "control": adapter.recorder.events[1]["body"] = "wrong-resource"
    else: native["status"] = 500
    assert finish(adapter)["native_trace_content_verdict"] == "inconclusive"


def test_other_paths_roles_or_methods_do_not_inflate_subject_read_coverage():
    for field, value in [("path", "/api/else"), ("method", "HEAD"), ("step", "native_owner_get")]:
        adapter = Adapter(); adapter.recorder.events[-1][field] = value
        assert finish(adapter)["native_trace_content_verdict"] == "not_exercised"


def test_schema_cannot_reverse_transition_and_keeps_native_media_type():
    for target, media in [("gitea", "text/plain"), ("pocketbase", "application/json")]:
        adapter = SimpleNamespace(path="/api/protected", fixture=SimpleNamespace(target=target))
        schema = matched.read_schema(adapter, "http://127.0.0.1:1234")
        assert list(schema["paths"]) == [adapter.path]
        assert list(schema["paths"][adapter.path]) == ["get"]
        assert media in schema["paths"][adapter.path]["get"]["responses"]["200"]["content"]


def test_freeze_resume_and_evidence_integrity(tmp_path, monkeypatch):
    protocol_path = tmp_path / "freeze.json"
    protocol = campaign.freeze(ROOT, protocol_path)
    assert campaign.load_protocol(protocol_path, ROOT) == protocol
    assert len(set(campaign.work_items(protocol))) == 36
    with pytest.raises(ValueError): campaign.freeze(ROOT, protocol_path)
    # A small isolated protocol exercises resume without launching external tools.
    protocol.update(targets=["gitea"], generations=["old"], drivers=["scripted"], seeds=[1000])
    protocol["protocol_sha256"] = campaign.canonical_digest({k: v for k, v in protocol.items() if k != "protocol_sha256"})
    calls = []
    def scripted(target, tools, base, generation, protocol):
        directory = base / "scripted-test"; directory.mkdir(parents=True)
        (directory / "events.jsonl").write_text('{}\n')
        calls.append(1)
        return {"status": "execution_error"}, directory
    monkeypatch.setattr(campaign, "scripted", scripted)
    output = tmp_path / "output"
    campaign.run(protocol, output, tmp_path)
    campaign.run(protocol, output, tmp_path)
    assert len(calls) == 1
    result = campaign.analyze(protocol, output)
    assert result["all_rows_recorded"] and result["summaries"][0]["completed"] == 0
    assert result["recall"] is None and not result["claims"]["relative_effectiveness"]
    row = campaign.read_rows(output, protocol)[0]
    evidence = output / row["directory"] / "events.jsonl"
    evidence.write_text('changed\n')
    with pytest.raises(ValueError, match="evidence changed"): campaign.read_rows(output, protocol)


def test_protocol_edit_and_torn_rows_are_rejected(tmp_path):
    path = tmp_path / "protocol.json"
    protocol = campaign.freeze(ROOT, path)
    modified = deepcopy(protocol); modified["max_requests"] = 1000
    path.write_text(json.dumps(modified))
    with pytest.raises(ValueError, match="hash/schema"): campaign.load_protocol(path, ROOT)
    (tmp_path / "rows.jsonl").write_text('{"key":')
    with pytest.raises(ValueError): campaign.read_rows(tmp_path, protocol)


def test_private_evidence_cannot_hide_symlinks(tmp_path):
    (tmp_path / "hidden").symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="Symlink"): campaign.evidence_index(tmp_path)
