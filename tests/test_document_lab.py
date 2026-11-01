"""Ground-truth target tests, independent of the future tester and oracle."""

from contextlib import ExitStack
import math
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from document_lab.app import create_app
from document_lab.settings import LabSettings
from temporal_auth.config import load_config

MODES = ("immediate", "delayed", "stale_session")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def lab_factory():
    with ExitStack() as stack:
        def factory(mode="immediate", **overrides):
            clock = Clock()
            settings = LabSettings(mode=mode, **overrides)
            client = stack.enter_context(TestClient(create_app(settings, clock=clock)))
            return client, clock
        yield factory


def login(client, username):
    response = client.post("/auth/login", json={"username": username, "password": f"{username}-demo-password"})
    assert response.status_code == 200, response.text
    user = response.json()
    return user, {"Authorization": f"Bearer {user['access_token']}"}


def shared_document(client):
    owner, owner_headers = login(client, "alice")
    subject, _ = login(client, "bob")
    marker = f"protected-{uuid4()}"
    created = client.post("/documents", headers=owner_headers, json={"content": marker})
    assert created.status_code == 201
    document = created.json()
    document_id = document["id"]
    assert document["owner_id"] == owner["user_id"]
    assert client.post(
        f"/documents/{document_id}/shares", headers=owner_headers,
        json={"subject_id": subject["user_id"]},
    ).status_code == 200
    _, old_headers = login(client, "bob")
    assert client.get(f"/documents/{document_id}", headers=old_headers).json()["content"] == marker
    return document_id, subject["user_id"], owner_headers, old_headers, marker


def revoke(client, document_id, subject_id, headers):
    response = client.delete(f"/documents/{document_id}/shares/{subject_id}", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["max_delay_seconds"] == 5.0


def assert_denied(response, marker):
    assert response.status_code == 403
    assert marker not in response.text


@pytest.mark.parametrize("mode", MODES)
def test_old_and_fresh_sessions_after_declared_bound(lab_factory, mode):
    client, clock = lab_factory(mode)
    doc, bob, owner, old, marker = shared_document(client)
    revoke(client, doc, bob, owner)
    _, fresh = login(client, "bob")
    clock.advance(5.05)
    old_response = client.get(f"/documents/{doc}", headers=old)
    if mode == "stale_session":
        assert old_response.status_code == 200
        assert old_response.json()["content"] == marker
    else:
        assert_denied(old_response, marker)
    assert_denied(client.get(f"/documents/{doc}", headers=fresh), marker)
    control = client.get(f"/documents/{doc}", headers=owner)
    assert control.status_code == 200
    assert control.json()["content"] == marker


def test_immediate_mode_denies_without_waiting(lab_factory):
    client, _ = lab_factory()
    doc, bob, owner, old, marker = shared_document(client)
    revoke(client, doc, bob, owner)
    assert_denied(client.get(f"/documents/{doc}", headers=old), marker)


def test_delayed_mode_allows_before_bound_and_denies_at_boundary(lab_factory):
    client, clock = lab_factory("delayed")
    doc, bob, owner, old, marker = shared_document(client)
    revoke(client, doc, bob, owner)
    _, fresh = login(client, "bob")
    clock.advance(4.999)
    for headers in (old, fresh):
        assert client.get(f"/documents/{doc}", headers=headers).json()["content"] == marker
    clock.advance(0.001)
    for headers in (old, fresh):
        assert_denied(client.get(f"/documents/{doc}", headers=headers), marker)


def test_repeated_revoke_does_not_extend_grace(lab_factory):
    client, clock = lab_factory("delayed")
    doc, bob, owner, old, marker = shared_document(client)
    revoke(client, doc, bob, owner)
    clock.advance(4)
    revoke(client, doc, bob, owner)
    clock.advance(1)
    assert_denied(client.get(f"/documents/{doc}", headers=old), marker)


@pytest.mark.parametrize("mode", MODES)
def test_regrant_restores_access_and_later_revoke_uses_new_time(lab_factory, mode):
    client, clock = lab_factory(mode)
    doc, bob, owner, old, marker = shared_document(client)
    revoke(client, doc, bob, owner)
    clock.advance(6)
    assert client.post(f"/documents/{doc}/shares", headers=owner, json={"subject_id": bob}).status_code == 200
    assert client.get(f"/documents/{doc}", headers=old).json()["content"] == marker
    revoke(client, doc, bob, owner)
    if mode == "delayed":
        assert client.get(f"/documents/{doc}", headers=old).status_code == 200
    clock.advance(5)
    response = client.get(f"/documents/{doc}", headers=old)
    if mode == "stale_session":
        assert response.json()["content"] == marker
    else:
        assert_denied(response, marker)


@pytest.mark.parametrize("mode", MODES)
def test_unrelated_user_never_receives_protected_content(lab_factory, mode):
    client, clock = lab_factory(mode)
    doc, bob, owner, _, marker = shared_document(client)
    _, outsider = login(client, "charlie")
    assert_denied(client.get(f"/documents/{doc}", headers=outsider), marker)
    revoke(client, doc, bob, owner)
    clock.advance(6)
    assert_denied(client.get(f"/documents/{doc}", headers=outsider), marker)


@pytest.mark.parametrize("mode", MODES)
def test_session_created_before_grant_can_read_new_share(lab_factory, mode):
    client, _ = lab_factory(mode)
    subject, headers = login(client, "bob")
    _, owner = login(client, "alice")
    doc = client.post("/documents", headers=owner, json={"content": "newly-shared"}).json()["id"]
    assert client.get(f"/documents/{doc}", headers=headers).status_code == 403
    assert client.post(f"/documents/{doc}/shares", headers=owner, json={"subject_id": subject["user_id"]}).status_code == 200
    assert client.get(f"/documents/{doc}", headers=headers).json()["content"] == "newly-shared"


def test_non_owner_cannot_change_sharing(lab_factory):
    client, _ = lab_factory()
    doc, bob, owner, subject, marker = shared_document(client)
    outsider, outsider_headers = login(client, "charlie")
    for headers in (subject, outsider_headers):
        assert client.post(f"/documents/{doc}/shares", headers=headers, json={"subject_id": outsider["user_id"]}).status_code == 403
        assert client.delete(f"/documents/{doc}/shares/{bob}", headers=headers).status_code == 403
    assert client.get(f"/documents/{doc}", headers=subject).json()["content"] == marker
    assert_denied(client.get(f"/documents/{doc}", headers=outsider_headers), marker)
    assert client.get(f"/documents/{doc}", headers=owner).status_code == 200


def test_reset_is_key_protected_and_invalidates_all_old_state(lab_factory):
    client, _ = lab_factory("stale_session")
    doc, old_bob, owner, subject, marker = shared_document(client)
    for headers in ({}, {"X-Lab-Reset-Key": "wrong"}):
        assert client.post("/testing/reset", headers=headers).status_code == 403
    assert client.get(f"/documents/{doc}", headers=subject).json()["content"] == marker
    assert client.post("/testing/reset", headers={"X-Lab-Reset-Key": "local-lab-reset-key"}).status_code == 200
    for headers in (owner, subject):
        assert client.get(f"/documents/{doc}", headers=headers).status_code == 401
    new_bob, _ = login(client, "bob")
    assert new_bob["user_id"] != old_bob
    _, new_owner = login(client, "alice")
    assert client.get(f"/documents/{doc}", headers=new_owner).status_code == 404
    new_doc = client.post("/documents", headers=new_owner, json={"content": "fresh"}).json()["id"]
    assert new_doc != doc


def test_app_instances_do_not_share_sessions_or_documents(lab_factory):
    first, _ = lab_factory()
    second, _ = lab_factory()
    doc, _, owner, _, _ = shared_document(first)
    assert second.get(f"/documents/{doc}", headers=owner).status_code == 401
    _, other_owner = login(second, "alice")
    assert second.get(f"/documents/{doc}", headers=other_owner).status_code == 404


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid-token"}, {"Authorization": "Basic abc"}])
def test_document_operations_require_valid_authentication(lab_factory, headers):
    client, _ = lab_factory()
    response = client.post("/documents", headers=headers, json={"content": "private"})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_login_and_invalid_inputs_do_not_create_access(lab_factory):
    client, _ = lab_factory()
    for username in ("alice", "missing-user"):
        response = client.post("/auth/login", json={"username": username, "password": "wrong"})
        assert response.status_code == 401
        assert "access_token" not in response.json()
    _, owner = login(client, "alice")
    assert client.post("/documents", headers=owner, json={"content": ""}).status_code == 422
    assert client.post("/documents", headers=owner, json={"content": "valid", "owner_id": "bob"}).status_code == 422
    created = client.post("/documents", headers=owner, json={"content": "valid"}).json()
    assert client.post(f"/documents/{created['id']}/shares", headers=owner, json={"subject_id": "unknown"}).status_code == 404


def test_responses_disable_caching_and_openapi_matches_config(lab_factory, example_path):
    client, _ = lab_factory()
    assert client.get("/health").headers["cache-control"] == "no-store"
    schema = client.get("/openapi.json").json()
    config = load_config(example_path)
    for operation_id, operation in config.operations.items():
        defined = schema["paths"][operation.path][operation.method.lower()]
        assert defined["operationId"] == operation_id
    assert "/testing/reset" not in schema["paths"]


@pytest.mark.parametrize("delay", [-1, 5.1, math.inf, math.nan, True])
def test_lab_cannot_accidentally_make_correct_delay_exceed_policy(delay):
    with pytest.raises(ValidationError):
        LabSettings(revocation_delay_seconds=delay)


def test_settings_can_be_configured_from_environment(monkeypatch):
    monkeypatch.setenv("LAB_MODE", "delayed")
    monkeypatch.setenv("LAB_REVOCATION_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("LAB_ALICE_PASSWORD", "custom-fixture-password")
    settings = LabSettings.from_env()
    assert settings.mode == "delayed"
    assert settings.revocation_delay_seconds == 0.25
    assert settings.alice_password.get_secret_value() == "custom-fixture-password"
    assert "custom-fixture-password" not in repr(settings)


def test_unknown_lab_mode_is_rejected():
    with pytest.raises(ValidationError):
        LabSettings(mode="misspelled-mode")
