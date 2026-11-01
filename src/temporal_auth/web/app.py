"""Loopback-only FastAPI workspace with server-rendered HTML and a durable queue."""

from contextlib import asynccontextmanager
import os
from pathlib import Path
import secrets
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from temporal_auth.web.evidence import export_bundle, inspect_evidence
from temporal_auth.web.models import JobSpec, preview
from temporal_auth.web.store import ACTIVE, Store
from temporal_auth.web.supervisor import Supervisor


LABELS = {"confirmed_violation": "Confirmed violation", "candidate": "Candidate", "no_violation_observed": "No violation observed",
          "inconclusive": "Inconclusive", "not_evaluated": "Not evaluated", "pending": "Checking",
          "queued": "Queued", "running": "Running", "cancelling": "Cancelling", "cancelled": "Cancelled",
          "interrupted": "Interrupted", "failed": "Failed", "completed": "Completed"}
TARGETS = {"managed_lab": "Document lab", "configured_lab": "Configured lab", "gitea": "Gitea", "pocketbase": "PocketBase"}
LIFECYCLES = {"sharing_revocation": "Sharing revocation", "role_downgrade": "Role downgrade", "ownership_transfer": "Ownership transfer"}


def create_app(data_dir=None, tools_dir=None, *, start_worker=True, metrics_port=None):
    root = Path(data_dir or os.environ.get("TEMPORAL_AUTH_WEB_DATA", "artifacts/workspace")).resolve()
    tools = Path(tools_dir or os.environ.get("TEMPORAL_AUTH_TOOLS", "artifacts/tools")).resolve()
    store = Store(root)
    supervisor = Supervisor(store, tools, metrics_port=metrics_port)
    csrf = secrets.token_urlsafe(32)
    templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
    templates.env.globals.update(labels=LABELS, targets=TARGETS, lifecycles=LIFECYCLES, active_states=ACTIVE)

    @asynccontextmanager
    async def lifespan(app):
        if start_worker: await supervisor.start()
        yield
        if start_worker: await supervisor.close()

    app = FastAPI(title="Temporal Auth workspace", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.supervisor, app.state.csrf = store, supervisor, csrf
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])

    @app.middleware("http")
    async def local_boundary(request, call_next):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            expected_origin = f"{request.url.scheme}://{request.url.netloc}"
            if (request.headers.get("origin", expected_origin) != expected_origin
                    or request.headers.get("sec-fetch-site") == "cross-site"
                    or not secrets.compare_digest(request.headers.get("x-csrf-token", "").encode(), csrf.encode())):
                return JSONResponse({"detail": "Reload the workspace and try again from its local tab."}, status_code=403)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    async def validated(request):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 100_000: raise HTTPException(413, "Configuration exceeds 100 KB.")
        try:
            spec = JobSpec.model_validate_json(body)
            info = preview(spec, dict(os.environ))
        except (ValidationError, ValueError):
            # Validation details can include arbitrary YAML keys; use a stable
            # user-facing error without reflecting the supplied configuration.
            raise HTTPException(422, "Check the configuration, supported target, policy and budgets. Configured labs need valid YAML, a loopback address and reset acknowledgement.") from None
        return spec, info

    def get_job(identifier):
        try: UUID(identifier)
        except ValueError: raise HTTPException(404, "Experiment not found.") from None
        job = store.get(identifier)
        if not job: raise HTTPException(404, "Experiment not found.")
        return job

    def render(request, template, **context):
        return templates.TemplateResponse(request=request, name=template,
            context={"csrf": csrf, "worker_healthy": supervisor.healthy, "worker_error": supervisor.error, **context})

    def decorate(job):
        job["display_target"] = TARGETS[job["spec"]["target"]]
        job["display_lifecycle"] = LIFECYCLES[job["spec"]["lifecycle"]]
        return job

    @app.get("/health")
    def health(): return {"status": "ok", "worker": supervisor.healthy}

    @app.get("/")
    def index(request: Request, view: str = "all"):
        if view not in ("all", "active", "findings", "inconclusive"): view = "all"
        jobs = [decorate(job) for job in store.list(view)]
        return render(request, "index.html", jobs=jobs, view=view, nav="findings" if view == "findings" else "experiments")

    @app.get("/fragments/jobs")
    def jobs_fragment(request: Request, view: str = "all"):
        return render(request, "jobs.html", jobs=[decorate(job) for job in store.list(view)], view=view)

    @app.get("/new")
    def new(request: Request): return render(request, "new.html", nav="new")

    @app.post("/api/validate")
    async def validate(request: Request):
        _, info = await validated(request)
        return info

    @app.post("/api/jobs", status_code=202)
    async def create(request: Request):
        spec, info = await validated(request)
        if info["missing_credentials"]:
            raise HTTPException(422, "Set the credential environment references on the server before starting this lab.")
        if spec.target in ("gitea", "pocketbase") and not (tools / spec.target).is_file():
            raise HTTPException(422, "Install the pinned native application binaries with scripts/fetch_pilot_tools.py first.")
        try: identifier = store.create(spec)
        except ValueError: raise HTTPException(409, "The queue is full. Wait for current experiments to finish.") from None
        return {"id": identifier, "url": f"/runs/{identifier}"}

    @app.get("/api/jobs")
    def jobs_api(): return store.list()

    @app.get("/api/jobs/{identifier}")
    def job_api(identifier: str):
        job = get_job(identifier)
        evidence = inspect_evidence(root / "jobs" / identifier, job)
        return {**job, "observation": evidence["result"]}

    @app.post("/api/jobs/{identifier}/cancel")
    def cancel(identifier: str):
        get_job(identifier)
        return store.cancel(identifier)

    @app.post("/api/jobs/{identifier}/replay", status_code=202)
    def replay(identifier: str):
        job = get_job(identifier)
        if job["status"] in ACTIVE: raise HTTPException(409, "Wait for this experiment to stop before replaying it.")
        spec = JobSpec.model_validate(job["spec"])
        spec.title = (spec.title[:86] + " · replay")
        try: next_id = store.create(spec)
        except ValueError: raise HTTPException(409, "The queue is full.") from None
        return {"id": next_id, "url": f"/runs/{next_id}"}

    def detail_context(identifier):
        job = decorate(get_job(identifier))
        evidence = inspect_evidence(root / "jobs" / identifier, job)
        return {"job": job, **evidence, "nav": "experiments"}

    @app.get("/runs/{identifier}")
    def detail(request: Request, identifier: str): return render(request, "detail.html", **detail_context(identifier))

    @app.get("/runs/{identifier}/live")
    def live(request: Request, identifier: str): return render(request, "live.html", **detail_context(identifier))

    @app.get("/runs/{identifier}/evidence")
    def evidence_page(request: Request, identifier: str): return render(request, "evidence.html", **detail_context(identifier))

    @app.get("/runs/{identifier}/download")
    def download(identifier: str):
        job = get_job(identifier)
        if job["status"] in ACTIVE: raise HTTPException(409, "Stop the experiment before exporting a consistent bundle.")
        try: data = export_bundle(root / "jobs" / identifier, job)
        except ValueError: raise HTTPException(413, "Evidence exceeds the 64 MB browser export limit.") from None
        return Response(data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="temporal-auth-{identifier}.zip"'})

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app
