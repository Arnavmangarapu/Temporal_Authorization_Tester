"""FastAPI factory for the controlled local target; not the tester's web UI."""

from collections.abc import Callable
from contextlib import asynccontextmanager
import hmac
from time import monotonic
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from document_lab.settings import LabSettings, POLICY_BOUND_SECONDS
from document_lab.store import LabError, LabStore

bearer = HTTPBearer(auto_error=False)


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginInput(InputModel):
    username: str = Field(min_length=1, max_length=100)
    password: SecretStr = Field(min_length=1, max_length=1000)


class LoginOutput(BaseModel):
    access_token: str
    token_type: Literal["bearer"]
    user_id: str
    username: str


class DocumentInput(InputModel):
    content: str = Field(min_length=1, max_length=100_000)
    access_model: Literal["sharing", "role", "ownership"] = "sharing"


class WriteInput(InputModel):
    content: str = Field(min_length=1, max_length=100_000)


class RoleInput(InputModel):
    role: Literal["editor", "viewer"]


class OwnerInput(InputModel):
    new_owner_id: str = Field(min_length=1, max_length=100)


class DocumentOutput(BaseModel):
    id: str
    owner_id: str
    content: str


class ShareInput(InputModel):
    subject_id: str = Field(min_length=1, max_length=100)
    permission: Literal["read", "write"] = "read"


class ShareOutput(BaseModel):
    document_id: str
    subject_id: str
    status: Literal["granted", "revoked"]


class RevokeOutput(ShareOutput):
    max_delay_seconds: float


def get_store(request: Request) -> LabStore:
    return request.app.state.store


def get_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> str:
    if credentials is None:
        raise HTTPException(401, "Bearer session required", headers={"WWW-Authenticate": "Bearer"})
    return credentials.credentials


Store = Annotated[LabStore, Depends(get_store)]
Token = Annotated[str, Depends(get_token)]


def create_app(
    settings: LabSettings | None = None, *, clock: Callable[[], float] = monotonic,
) -> FastAPI:
    settings = settings if settings is not None else LabSettings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = LabStore(settings, clock)
        app.state.store = store
        try:
            yield
        finally:
            store.close()

    app = FastAPI(
        title="Document Sharing Laboratory",
        description="Controlled local benchmark with selectable revocation behavior. Uses disposable fixture accounts.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def prevent_response_caching(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(LabError)
    async def handle_lab_error(request: Request, error: LabError):
        headers = {"WWW-Authenticate": "Bearer"} if error.status == 401 else None
        return JSONResponse({"detail": error.detail}, status_code=error.status, headers=headers)

    @app.get("/health", operation_id="health")
    def health():
        return {"status": "ok"}

    @app.post("/auth/login", response_model=LoginOutput, operation_id="login")
    def login(body: LoginInput, store: Store):
        return store.login(body.username, body.password.get_secret_value())

    @app.post("/documents", response_model=DocumentOutput, status_code=201, operation_id="create_document")
    def create_document(body: DocumentInput, store: Store, token: Token):
        return store.create_document(token, body.content, body.access_model)

    @app.get("/documents/{document_id}", response_model=DocumentOutput, operation_id="read_document")
    def read_document(document_id: str, store: Store, token: Token):
        return store.read(token, document_id)

    @app.post("/documents/{document_id}/shares", response_model=ShareOutput, operation_id="grant_share")
    def grant_share(document_id: str, body: ShareInput, store: Store, token: Token):
        store.grant(token, document_id, body.subject_id, body.permission)
        return {"document_id": document_id, "subject_id": body.subject_id, "status": "granted"}

    @app.delete("/documents/{document_id}/shares/{subject_id}", response_model=RevokeOutput, operation_id="revoke_share")
    def revoke_share(document_id: str, subject_id: str, store: Store, token: Token):
        store.revoke(token, document_id, subject_id)
        return {
            "document_id": document_id, "subject_id": subject_id,
            "status": "revoked", "max_delay_seconds": POLICY_BOUND_SECONDS,
        }

    @app.patch("/documents/{document_id}", response_model=DocumentOutput, operation_id="write_document")
    def write_document(document_id: str, body: WriteInput, store: Store, token: Token):
        return store.write(token, document_id, body.content)

    @app.post("/users/{subject_id}/role", operation_id="change_role")
    def change_role(subject_id: str, body: RoleInput, store: Store, token: Token):
        store.change_role(token, subject_id, body.role)
        return {"subject_id": subject_id, "role": body.role, "status": "role_changed", "max_delay_seconds": POLICY_BOUND_SECONDS}

    @app.post("/documents/{document_id}/owner", operation_id="transfer_owner")
    def transfer_owner(document_id: str, body: OwnerInput, store: Store, token: Token):
        store.transfer(token, document_id, body.new_owner_id)
        return {"document_id": document_id, "new_owner_id": body.new_owner_id, "status": "ownership_transferred", "max_delay_seconds": POLICY_BOUND_SECONDS}

    @app.post("/testing/reset", operation_id="reset_fixture", include_in_schema=False)
    def reset_fixture(store: Store, key: Annotated[str | None, Header(alias="X-Lab-Reset-Key")] = None):
        expected = settings.reset_key.get_secret_value().encode()
        if key is None or not hmac.compare_digest(key.encode(), expected):
            raise HTTPException(403, "Fixture reset key required")
        store.reset()
        return {"status": "reset"}

    return app
