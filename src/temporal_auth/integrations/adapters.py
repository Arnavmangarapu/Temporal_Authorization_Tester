"""Native API workflows. No authorization decisions are made by these adapters."""

import base64
import secrets
from uuid import uuid4

from temporal_auth.integrations.fixtures import Fixture


class AdapterError(RuntimeError):
    pass


def require(response, statuses):
    if response.status_code not in statuses:
        raise AdapterError("unexpected_api_status")
    try:
        return response.json() if response.content else {}
    except ValueError:
        raise AdapterError("invalid_api_json") from None


class NativeAdapter:
    def __init__(self, fixture: Fixture, recorder):
        self.fixture = fixture
        self.recorder = recorder
        self.marker = "protected-" + uuid4().hex
        self.subject_password = secrets.token_urlsafe(24)
        recorder.redactor.add(fixture.password)
        recorder.redactor.add(self.subject_password)
        self.owner = {}
        self.sessions = {}
        self.subject_id = None
        self.resource_id = None
        self.path = None

    def call(self, step, method, path, *, session=None, json=None, auth=None, secret=False):
        return self.recorder.request(step, method, path, headers=session, json=json,
                                     auth=auth, secret=secret)

    def read(self, step, session):
        return self.call(step, "GET", self.path, session=session)


class PocketBaseAdapter(NativeAdapter):
    policy_source = (
        "Local single-process fixture policy: viewRule requires current authenticated "
        "role=editor; PATCH commits the role before acknowledgement. This is an "
        "annotated API-rule policy, not a vendor propagation SLA."
    )

    def login(self, generation):
        data = require(self.call(f"login_{generation}", "POST",
            f"/api/collections/{self.users}/auth-with-password",
            json={"identity": "subject@example.test", "password": self.subject_password},
            secret=True), {200})
        if data["record"]["id"] != self.subject_id:
            raise AdapterError("subject_identity_mismatch")
        token = data["token"]
        self.recorder.redactor.add(token)
        self.sessions[generation] = {"Authorization": token}
        return self.sessions[generation]

    def setup(self):
        data = require(self.call("login_owner", "POST",
            "/api/collections/_superusers/auth-with-password",
            json={"identity": self.fixture.username, "password": self.fixture.password},
            secret=True), {200})
        self.recorder.redactor.add(data["token"])
        self.owner = {"Authorization": data["token"]}
        suffix = uuid4().hex[:12]
        self.users = "actors_" + suffix
        self.documents = "documents_" + suffix
        require(self.call("create_auth_collection", "POST", "/api/collections", session=self.owner,
            json={"name": self.users, "type": "auth", "passwordAuth": {"enabled": True,
                  "identityFields": ["email"]}, "fields": [
                  {"name": "role", "type": "select", "values": ["editor", "viewer"],
                   "maxSelect": 1, "required": True}]}), {200})
        data = require(self.call("create_subject", "POST",
            f"/api/collections/{self.users}/records", session=self.owner,
            json={"email": "subject@example.test", "password": self.subject_password,
                  "passwordConfirm": self.subject_password, "role": "editor"}, secret=True), {200})
        self.subject_id = data["id"]
        require(self.call("create_document_collection", "POST", "/api/collections", session=self.owner,
            json={"name": self.documents, "type": "base", "viewRule":
                  f'@request.auth.collectionName = "{self.users}" && @request.auth.role = "editor"',
                  "fields": [{"name": "content", "type": "text", "required": True}]}), {200})
        data = require(self.call("create_resource", "POST",
            f"/api/collections/{self.documents}/records", session=self.owner,
            json={"content": self.marker}), {200})
        self.resource_id = data["id"]
        self.path = f"/api/collections/{self.documents}/records/{self.resource_id}"

    def transition(self):
        data = require(self.call("transition", "PATCH",
            f"/api/collections/{self.users}/records/{self.subject_id}", session=self.owner,
            json={"role": "viewer"}), {200})
        if data.get("id") != self.subject_id or data.get("role") != "viewer":
            raise AdapterError("transition_not_acknowledged")

    def verify_transition(self):
        data = require(self.call("transition_control", "GET",
            f"/api/collections/{self.users}/records/{self.subject_id}", session=self.owner), {200})
        if data.get("role") != "viewer" or data.get("id") != self.subject_id:
            raise AdapterError("transition_state_mismatch")

    def create_attacker(self):
        require(self.call("create_attacker", "POST", f"/api/collections/{self.users}/records",
            session=self.owner, json={"email": "attacker@example.test", "password": self.subject_password,
            "passwordConfirm": self.subject_password, "role": "viewer"}, secret=True), {200})
        data = require(self.call("login_attacker", "POST", f"/api/collections/{self.users}/auth-with-password",
            json={"identity": "attacker@example.test", "password": self.subject_password}, secret=True), {200})
        self.recorder.redactor.add(data["token"])
        return {"Authorization": data["token"]}


class GiteaAdapter(NativeAdapter):
    policy_source = (
        "Local private-repository policy: the ordinary user is neither owner, admin "
        "nor an organization/team member; collaborator deletion is synchronous in "
        "the pinned handler. No vendor propagation SLA is asserted."
    )

    def login(self, generation):
        data = require(self.call(f"login_{generation}", "POST", "/api/v1/users/subject/tokens",
            auth=("subject", self.subject_password), json={"name": "pilot-" + uuid4().hex,
            "scopes": ["read:repository", "read:user"]}, secret=True), {201})
        token = data["sha1"]
        self.recorder.redactor.add(token)
        self.sessions[generation] = {"Authorization": "token " + token}
        identity = require(self.call(f"identity_{generation}", "GET", "/api/v1/user",
                                    session=self.sessions[generation]), {200})
        if identity.get("id") != self.subject_id or identity.get("is_admin"):
            raise AdapterError("subject_identity_mismatch")
        return self.sessions[generation]

    def setup(self):
        data = require(self.call("login_owner", "POST", "/api/v1/users/owner/tokens",
            auth=(self.fixture.username, self.fixture.password),
            json={"name": "owner-" + uuid4().hex, "scopes": ["all"]}, secret=True), {201})
        self.recorder.redactor.add(data["sha1"])
        self.owner = {"Authorization": "token " + data["sha1"]}
        data = require(self.call("create_subject", "POST", "/api/v1/admin/users", session=self.owner,
            json={"username": "subject", "email": "subject@example.test",
                  "password": self.subject_password, "must_change_password": False,
                  "send_notify": False}, secret=True), {201})
        self.subject_id = data["id"]
        if data.get("is_admin"):
            raise AdapterError("subject_must_be_ordinary_user")
        self.repo = "pilot-" + uuid4().hex[:12]
        data = require(self.call("create_resource", "POST", "/api/v1/user/repos", session=self.owner,
            json={"name": self.repo, "private": True, "auto_init": True}), {201})
        if data.get("private") is not True or data.get("owner", {}).get("login") != "owner":
            raise AdapterError("resource_not_private_or_wrong_owner")
        self.resource_id = data["id"]
        self.repo_path = f"/api/v1/repos/owner/{self.repo}"
        require(self.call("create_content", "POST", self.repo_path + "/contents/protected.txt",
            session=self.owner, json={"content": base64.b64encode(self.marker.encode()).decode(),
            "message": "Create disposable authorization probe"}), {201})
        self.path = self.repo_path + "/raw/protected.txt"
        self.collaborator = self.repo_path + "/collaborators/subject"
        require(self.call("establish_access", "PUT", self.collaborator,
                          session=self.owner, json={"permission": "read"}), {204})

    def transition(self):
        require(self.call("transition", "DELETE", self.collaborator, session=self.owner), {204})

    def verify_transition(self):
        require(self.call("transition_control", "GET", self.collaborator, session=self.owner), {404})

    def create_attacker(self):
        data = require(self.call("create_attacker", "POST", "/api/v1/admin/users", session=self.owner,
            json={"username": "attacker", "email": "attacker@example.test", "password": self.subject_password,
                  "must_change_password": False, "send_notify": False}, secret=True), {201})
        if data.get("is_admin"):
            raise AdapterError("subject_must_be_ordinary_user")
        data = require(self.call("login_attacker", "POST", "/api/v1/users/attacker/tokens",
            auth=("attacker", self.subject_password), json={"name": "attacker-" + uuid4().hex,
            "scopes": ["read:repository", "read:user"]}, secret=True), {201})
        self.recorder.redactor.add(data["sha1"])
        return {"Authorization": "token " + data["sha1"]}


ADAPTERS = {"pocketbase": PocketBaseAdapter, "gitea": GiteaAdapter}
