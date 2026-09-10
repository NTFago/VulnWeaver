"""FastAPI application for projects, artifacts, tasks, and task events."""
# pyright: reportUnusedFunction=false

import asyncio
import hashlib
import logging
from collections.abc import Iterable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Annotated, Any, cast
from uuid import uuid4

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    Security,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse
from fastapi.security import APIKeyCookie
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    AgentRun,
    Annotation,
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    Finding,
    Job,
    PairFunction,
    Poc,
    PocKind,
    Project,
    ProofRequest,
    QueueEvent,
    ResourceBudget,
    Review,
    SchemaVersion,
    Task,
    TaskStatus,
    ToolIdentity,
    validate_contract,
)
from vulnweaver_domain import normalize_idempotency_key
from vulnweaver_orchestrator import FindingReviewGate
from vulnweaver_persistence import Database, DatabaseSettings, EntityNotFound, IdempotencyConflict
from vulnweaver_persistence.fingerprints import request_fingerprint
from vulnweaver_proof import ProofJobScheduler
from vulnweaver_reporting import ReportJobScheduler

from vulnweaver_api.auth import (
    SESSION_COOKIE,
    AuthenticationFailed,
    PasswordChangeRequired,
    PersonalAuthService,
)
from vulnweaver_api.cookies import delete_session_cookies, set_session_cookies
from vulnweaver_api.errors import ApiInputError, install_error_handlers
from vulnweaver_api.events import task_cancelled, task_requested
from vulnweaver_api.middleware import CorrelationIdMiddleware, RequestBodyLimitMiddleware
from vulnweaver_api.schemas import (
    ArtifactDetail,
    CreateAnnotationBody,
    CreateProjectBody,
    CreateProofJobBody,
    CreateReportJobBody,
    CreateTaskBody,
    ErrorResponse,
    FindingEvidenceDetail,
    HealthResponse,
    InstallationStatusResponse,
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
    ProductSettingsBody,
    ProductSettingsResponse,
    RegistrationRequest,
    ReviewFindingBody,
    SessionResponse,
)
from vulnweaver_api.settings import ApiSettings
from vulnweaver_api.uploads import remove_stale_uploads, stage_upload

LOGGER = logging.getLogger(__name__)
IDEMPOTENCY_HEADER = Header(alias="Idempotency-Key", min_length=8, max_length=128)
CSRF_HEADER = Header(alias="X-CSRF-Token", min_length=8, max_length=256)


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    configuration = settings or ApiSettings.from_env()
    database = Database(DatabaseSettings(configuration.database_url))
    store = LocalContentAddressedStore(configuration.artifact_store_root)
    auth = PersonalAuthService(
        database,
        session_ttl_seconds=configuration.session_ttl_seconds,
        failure_threshold=configuration.login_failure_threshold,
        lockout_seconds=configuration.login_lockout_seconds,
        max_password_concurrency=configuration.max_password_concurrency,
        max_active_sessions=configuration.max_active_sessions,
    )
    upload_slots = asyncio.Semaphore(configuration.max_upload_concurrency)
    review_gate = FindingReviewGate(database)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await auth.initialize()
        await asyncio.to_thread(remove_stale_uploads, configuration.upload_staging_root)
        yield
        await database.dispose()

    app = FastAPI(
        title="VulnWeaver API",
        version="1.0.0",
        lifespan=lifespan,
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            413: {"model": ErrorResponse},
            415: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
            500: {"model": ErrorResponse},
        },
    )
    app.add_middleware(
        RequestBodyLimitMiddleware,
        json_max_body_size=configuration.json_body_max_bytes,
        upload_max_body_size=configuration.request_body_max_bytes,
    )
    app.add_middleware(CorrelationIdMiddleware)
    app.state.database = database
    app.state.store = store
    app.state.auth = auth
    app.state.settings = configuration

    install_error_handlers(app)

    session_cookie = APIKeyCookie(name=SESSION_COOKIE, auto_error=False)

    async def require_account(
        request: Request,
        session: Annotated[str | None, Security(session_cookie)],
    ) -> str:
        await auth.authenticate(session)
        request.state.session_token = session
        assert session is not None
        return session

    async def require_write(
        request: Request,
        session: Annotated[str | None, Security(session_cookie)],
        csrf_token: Annotated[str | None, CSRF_HEADER] = None,
    ) -> str:
        await auth.authenticate_write(session, csrf_token)
        assert session is not None
        request.state.session_token = session
        return session

    @app.post("/api/auth/login", response_model=SessionResponse)
    async def login(body: LoginRequest, response: Response) -> SessionResponse:
        validate_contract("LoginRequest", body.model_dump(mode="json"))
        result = await auth.login(body.username, body.password)
        set_session_cookies(
            response,
            session_token=result.token,
            csrf_token=result.csrf_token,
            secure=configuration.secure_cookie,
            max_age=configuration.session_ttl_seconds,
        )
        return SessionResponse(
            username=result.account.username,
            must_change_password=result.account.must_change_password,
            csrf_token=result.csrf_token,
        )

    @app.get("/api/auth/installation", response_model=InstallationStatusResponse)
    async def installation_status() -> InstallationStatusResponse:
        return InstallationStatusResponse(registration_open=not await auth.is_initialized())

    @app.post("/api/auth/register", response_model=SessionResponse, status_code=201)
    async def register(body: RegistrationRequest, response: Response) -> SessionResponse:
        validate_contract("RegistrationRequest", body.model_dump(mode="json"))
        result = await auth.register(body.username, body.password)
        set_session_cookies(
            response,
            session_token=result.token,
            csrf_token=result.csrf_token,
            secure=configuration.secure_cookie,
            max_age=configuration.session_ttl_seconds,
        )
        return SessionResponse(
            username=result.account.username,
            must_change_password=False,
            csrf_token=result.csrf_token,
        )

    @app.get("/api/auth/me", response_model=MeResponse)
    async def me(
        session: Annotated[str | None, Security(session_cookie)],
    ) -> MeResponse:
        authenticated = await auth.authenticate(session, allow_password_change=True)
        return MeResponse(
            username=authenticated.account.username,
            must_change_password=authenticated.account.must_change_password,
        )

    @app.post("/api/auth/logout", status_code=204)
    async def logout(
        response: Response,
        session: Annotated[str | None, Security(session_cookie)],
        csrf_token: Annotated[str | None, CSRF_HEADER] = None,
    ) -> None:
        if session is not None:
            try:
                await auth.authenticate(session, allow_password_change=True)
            except AuthenticationFailed:
                delete_session_cookies(response, secure=configuration.secure_cookie)
                return
            await auth.authenticate_write(session, csrf_token, allow_password_change=True)
        await auth.logout(session)
        delete_session_cookies(response, secure=configuration.secure_cookie)

    @app.post("/api/auth/password", status_code=204)
    async def change_password(
        body: PasswordChangeRequest,
        session: Annotated[str | None, Security(session_cookie)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
        csrf_token: Annotated[str | None, CSRF_HEADER] = None,
    ) -> None:
        validate_contract("PasswordChangeRequest", body.model_dump(mode="json"))
        await auth.change_password(
            session,
            csrf_token,
            body.current_password,
            body.new_password,
            idempotency_key=normalize_idempotency_key(idempotency_key),
        )

    @app.get("/api/settings", response_model=ProductSettingsResponse)
    async def get_product_settings(
        _: Annotated[str, Depends(require_account)],
    ) -> ProductSettingsResponse:
        async with database.transaction() as repositories:
            values = await repositories.product_settings.get()
        return _product_settings_response(values)

    @app.put("/api/settings", response_model=ProductSettingsResponse)
    async def put_product_settings(
        body: ProductSettingsBody,
        _: Annotated[str, Depends(require_write)],
    ) -> ProductSettingsResponse:
        values = body.model_dump(
            mode="json",
            exclude={
                "schema_version",
                "review_model_api_key",
                "clear_review_model_api_key",
            },
        )
        validate_contract("ProductSettings", body.model_dump(mode="json"))
        base_url = str(values["review_model_base_url"]).strip().rstrip("/")
        model_name = str(values["review_model_name"]).strip()
        if bool(base_url) != bool(model_name):
            raise ApiInputError(
                "incomplete_model_configuration",
                "model endpoint and model name must be configured together",
                "review_model_base_url",
            )
        if base_url and not base_url.startswith(("https://", "http://")):
            raise ApiInputError(
                "invalid_model_endpoint",
                "model endpoint must use HTTP or HTTPS",
                "review_model_base_url",
            )
        if body.clear_review_model_api_key and body.review_model_api_key is not None:
            raise ApiInputError(
                "conflicting_secret_update",
                "API key cannot be replaced and cleared in the same request",
                "clear_review_model_api_key",
            )
        values["review_model_base_url"] = base_url
        values["review_model_name"] = model_name
        async with database.transaction() as repositories:
            previous = await repositories.product_settings.get()
            stored_key = previous.get("review_model_api_key")
            if body.clear_review_model_api_key:
                stored_key = None
            elif body.review_model_api_key is not None:
                stored_key = body.review_model_api_key
            if stored_key is not None:
                values["review_model_api_key"] = stored_key
            await repositories.product_settings.replace(values)
        return _product_settings_response(values)

    @app.get("/health/live", response_model=HealthResponse)
    async def live() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.get("/health/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        await database.healthcheck()
        await asyncio.to_thread(store.healthcheck)
        return HealthResponse(status="ready")

    @app.get("/api/projects")
    async def list_projects(_: Annotated[str, Depends(require_account)]) -> list[Project]:
        async with database.transaction() as repositories:
            return await repositories.projects.list()

    @app.post("/api/projects", status_code=201)
    async def create_project(
        body: CreateProjectBody,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    ) -> Project:
        key = normalize_idempotency_key(idempotency_key)
        payload = body.model_dump(mode="json")
        validate_contract("CreateProjectRequest", payload)
        fingerprint = request_fingerprint(payload)
        async with database.transaction() as repositories:
            await repositories.api_requests.lock(scope="projects:create", key=key)
            prior = await repositories.api_requests.get(scope="projects:create", key=key)
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different API request"
                    )
                response.status_code = prior.response_status
                return await repositories.projects.get(prior.resource_id)
            project = Project(
                **payload,
                id=_identifier("project"),
                created_at=_now(),
            )
            await repositories.projects.add(project)
            await repositories.api_requests.add(
                scope="projects:create",
                key=key,
                fingerprint=fingerprint,
                resource_type="project",
                resource_id=project["id"],
                response_status=201,
            )
            return project

    @app.get("/api/projects/{project_id}")
    async def get_project(project_id: str, _: Annotated[str, Depends(require_account)]) -> Project:
        async with database.transaction() as repositories:
            return await repositories.projects.get(project_id)

    @app.get("/api/projects/{project_id}/artifacts")
    async def list_artifacts(
        project_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[Artifact]:
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)
            return await repositories.artifacts.list_for_project(project_id)

    @app.post(
        "/api/projects/{project_id}/artifacts",
        response_model=ArtifactDetail,
        status_code=201,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"}
                    }
                },
            }
        },
    )
    async def upload_artifact(
        project_id: str,
        request: Request,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
        kind: ArtifactKind,
        filename: Annotated[
            str | None, Header(alias="X-Artifact-Filename", max_length=512)
        ] = None,
    ) -> ArtifactDetail:
        key = normalize_idempotency_key(idempotency_key)
        _validate_upload_kind(kind)
        content_type = request.headers.get("content-type", "").partition(";")[0].lower()
        if content_type and content_type != "application/octet-stream":
            raise HTTPException(
                status_code=415,
                detail="artifact uploads require application/octet-stream",
            )
        # Reject an unknown project before consuming a potentially large body.
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)

        async with stage_upload(
            request,
            max_bytes=configuration.upload_max_bytes,
            staging_root=configuration.upload_staging_root,
            concurrency=upload_slots,
        ) as staged:
            if not staged.head:
                raise ApiInputError(
                    "empty_artifact", "uploaded artifact must not be empty", "body"
                )
            if not _matches_declared_format(kind, staged.head):
                raise ApiInputError(
                    "artifact_format_mismatch",
                    "content does not match the declared artifact kind",
                    "kind",
                )
            fingerprint = request_fingerprint(
                {"kind": str(kind), "digest": staged.digest}
            )
            scope = f"projects:{project_id}:artifacts:create"
            async with database.transaction() as repositories:
                await repositories.api_requests.lock(scope=scope, key=key)
                prior = await repositories.api_requests.get(scope=scope, key=key)
                if prior is not None:
                    if prior.request_fingerprint != fingerprint:
                        raise IdempotencyConflict(
                            "idempotency key was already used for a different upload"
                        )
                    response.status_code = prior.response_status
                    return await _artifact_detail(
                        repositories, project_id, prior.resource_id
                    )
                with staged.path.open("rb") as stream:
                    stored = await asyncio.to_thread(
                        store.put_stream,
                        stream,
                        max_bytes=configuration.upload_max_bytes,
                    )
                if stored.digest != staged.digest:
                    raise RuntimeError("staged artifact digest changed before publication")
                artifact_id = _identifier("artifact")
                version_id = _identifier("artifact-version")
                now = _now()
                artifact = Artifact(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=artifact_id,
                    project_id=project_id,
                    kind=kind,
                    current_version_id=version_id,
                    created_at=now,
                )
                version = ArtifactVersion(
                    schema_version=SchemaVersion.VALUE_1_0_0,
                    id=version_id,
                    artifact_id=artifact_id,
                    digest=stored.digest,
                    object_ref=stored.object_ref,
                    generation_config={"filename": filename or "upload"},
                    created_at=now,
                )
                await repositories.artifacts.add(artifact)
                await repositories.artifacts.add_version(version)
                await repositories.api_requests.add(
                    scope=scope,
                    key=key,
                    fingerprint=fingerprint,
                    resource_type="artifact",
                    resource_id=artifact_id,
                    response_status=201,
                )
                return ArtifactDetail(artifact=artifact, versions=[version])

    @app.get("/api/projects/{project_id}/artifacts/{artifact_id}", response_model=ArtifactDetail)
    async def get_artifact(
        project_id: str, artifact_id: str, _: Annotated[str, Depends(require_account)]
    ) -> ArtifactDetail:
        async with database.transaction() as repositories:
            return await _artifact_detail(repositories, project_id, artifact_id)

    @app.get("/api/artifacts/{artifact_id}/content")
    async def artifact_content(
        artifact_id: str,
        version_id: str | None = Query(default=None),
        _: Annotated[str, Depends(require_account)] = "",
    ) -> StreamingResponse:
        async with database.transaction() as repositories:
            artifact = await repositories.artifacts.get(artifact_id)
            version = await repositories.artifacts.get_version(
                version_id or artifact["current_version_id"]
            )
            if version["artifact_id"] != artifact_id:
                raise HTTPException(status_code=404, detail="artifact version not found")

        def chunks():
            with store.open(version["object_ref"]) as stream:
                while chunk := stream.read(1024 * 1024):
                    yield chunk

        return StreamingResponse(
            chunks(),
            media_type="application/octet-stream",
            headers={"ETag": f'"{version["digest"]}"'},
        )

    @app.get("/api/projects/{project_id}/tasks")
    async def list_tasks(
        project_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[Task]:
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)
            return await repositories.tasks.list_for_project(project_id)

    @app.post("/api/projects/{project_id}/tasks", status_code=201)
    async def create_task(
        project_id: str,
        body: CreateTaskBody,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    ) -> Task:
        key = normalize_idempotency_key(idempotency_key)
        payload = body.model_dump(mode="json")
        validate_contract("CreateTaskRequest", payload)
        now = _now()
        task = Task(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=_identifier("task"),
            project_id=project_id,
            artifact_version_ids=payload["artifact_version_ids"],
            status=TaskStatus.CREATED,
            result=None,
            idempotency_key=key,
            resource_budget=cast(ResourceBudget, payload["resource_budget"]),
            created_at=now,
            updated_at=now,
        )
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)
            for version_id in task["artifact_version_ids"]:
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                if artifact["project_id"] != project_id:
                    raise ApiInputError(
                        "artifact_project_mismatch",
                        "artifact version does not belong to this project",
                        "artifact_version_ids",
                    )
            result = await repositories.tasks.create(task)
            if not result.created:
                response.status_code = 200
                return result.value
            task_event = task_requested(result.value, now)
            await repositories.task_events.append(task_event)
            await repositories.outbox.add(task_event)
            return result.value

    @app.get("/api/tasks/{task_id}")
    async def get_task(task_id: str, _: Annotated[str, Depends(require_account)]) -> Task:
        async with database.transaction() as repositories:
            return await repositories.tasks.get(task_id)

    @app.post("/api/tasks/{task_id}/cancel")
    async def cancel_task(
        task_id: str,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    ) -> Task:
        key = normalize_idempotency_key(idempotency_key)
        fingerprint = request_fingerprint({"task_id": task_id, "operation": "cancel"})
        scope = f"tasks:{task_id}:cancel"
        async with database.transaction() as repositories:
            await repositories.api_requests.lock(scope=scope, key=key)
            prior = await repositories.api_requests.get(scope=scope, key=key)
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different cancellation"
                    )
                response.status_code = prior.response_status
                return await repositories.tasks.get(task_id)
            cancellation = await repositories.tasks.cancel(task_id)
            task = cancellation.task
            await repositories.jobs.cancel_for_task(task_id)
            if cancellation.changed:
                sequence = await repositories.task_events.next_sequence(task_id)
                event = task_cancelled(task, cancellation.previous_status, sequence)
                await repositories.task_events.append(event)
                await repositories.outbox.add(event)
            await repositories.api_requests.add(
                scope=scope,
                key=key,
                fingerprint=fingerprint,
                resource_type="task",
                resource_id=task_id,
                response_status=200,
            )
            return task

    @app.get("/api/tasks/{task_id}/jobs")
    async def task_jobs(task_id: str, _: Annotated[str, Depends(require_account)]) -> list[Job]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            return await repositories.jobs.list_for_task(task_id)

    @app.get("/api/jobs/{job_id}/result")
    async def job_result(job_id: str, _: Annotated[str, Depends(require_account)]) -> Any:
        async with database.transaction() as repositories:
            job = await repositories.jobs.get(job_id)
            result = await repositories.jobs.get_result(job_id)
            if result is None:
                return {"job_id": job["id"], "status": job["status"], "result": None}
            return result

    @app.get("/api/artifact-versions/{version_id}")
    async def artifact_version(
        version_id: str, _: Annotated[str, Depends(require_account)]
    ) -> ArtifactVersion:
        async with database.transaction() as repositories:
            return await repositories.artifacts.get_version(version_id)

    @app.get("/api/tasks/{task_id}/agent-runs")
    async def task_agent_runs(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[AgentRun]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            return await repositories.agent_runs.list_for_task(task_id)

    @app.get("/api/tasks/{task_id}/pair")
    async def task_pair(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[PairFunction]:
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            functions: list[PairFunction] = []
            for version_id in task["artifact_version_ids"]:
                functions.extend(await repositories.pair.list_functions(version_id))
            return functions

    @app.get("/api/tasks/{task_id}/pair/address/{address}")
    async def task_pair_at_address(
        task_id: str,
        address: int,
        _: Annotated[str, Depends(require_account)],
    ) -> list[PairFunction]:
        if address < 0:
            raise ApiInputError(
                "invalid_binary_address",
                "binary address must be non-negative",
                "address",
            )
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            functions: list[PairFunction] = []
            for version_id in task["artifact_version_ids"]:
                functions.extend(
                    await repositories.pair.functions_at_address(version_id, address)
                )
            return functions

    @app.get("/api/tasks/{task_id}/pair/function/{function_id}/neighborhood")
    async def task_pair_neighborhood(
        task_id: str,
        function_id: str,
        depth: int = 1,
        _: Annotated[str, Depends(require_account)] = "",
    ) -> dict[str, list[Any]]:
        """Return bounded caller/callee edges for a function in the task."""
        if depth < 1 or depth > 3:
            raise ApiInputError(
                "invalid_pair_depth", "pair neighborhood depth must be between 1 and 3", "depth"
            )
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            for version_id in task["artifact_version_ids"]:
                functions = await repositories.pair.list_functions(version_id)
                if any(function["id"] == function_id for function in functions):
                    neighborhood = await repositories.pair.neighborhood(
                        version_id, function_id, depth=depth
                    )
                    return neighborhood
        raise ApiInputError("pair_function_not_found", "pair function is not part of the task", "function_id")

    @app.get("/api/tasks/{task_id}/observability")
    async def task_observability(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> dict[str, Any]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            jobs = await repositories.jobs.list_for_task(task_id)
            events = await repositories.task_events.list_after(task_id)
            findings = await repositories.findings.list_for_task(task_id)
        failures: dict[str, int] = {}
        for job in jobs:
            failure = job["failure"]
            if failure is None:
                continue
            code = failure.get("code", "unknown")
            failures[code] = failures.get(code, 0) + 1
        return {
            "task_id": task_id,
            "jobs_total": len(jobs),
            "jobs_by_status": _count_values(job["status"] for job in jobs),
            "events_total": len(events),
            "findings_total": len(findings),
            "findings_by_status": _count_values(finding["status"] for finding in findings),
            "failures_by_code": failures,
        }

    @app.get("/api/tasks/{task_id}/findings")
    async def task_findings(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[Finding]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            return await repositories.findings.list_for_task(task_id)

    @app.post("/api/tasks/{task_id}/reports", status_code=202)
    async def create_report_job(
        task_id: str,
        body: CreateReportJobBody,
        _: Annotated[str, Depends(require_write)],
    ) -> Job:
        scheduler = ReportJobScheduler(
            tool=ToolIdentity(name="vulnweaver-report", version="1.0.0", image_digest=None)
        )
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id, for_update=True)
            source_version = await repositories.artifacts.get_version(body.version_id)
            source_artifact = await repositories.artifacts.get(body.artifact_id)
            if (
                source_version["artifact_id"] != source_artifact["id"]
                or source_artifact["project_id"] != task["project_id"]
            ):
                raise ApiInputError(
                    "report.source_mismatch",
                    "report source does not belong to the task project",
                    "artifact_id",
                )
            report_artifact_id = f"artifact:report:{task_id}:{body.format}"
            report_version_id = f"artifact-version:report:{task_id}:{body.format}"
            report_artifact = Artifact(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=report_artifact_id,
                project_id=task["project_id"],
                kind=ArtifactKind.DERIVED,
                current_version_id=report_version_id,
                created_at=task["updated_at"],
            )
            try:
                await repositories.artifacts.get(report_artifact_id)
            except EntityNotFound:
                await repositories.artifacts.add(report_artifact)
            return await scheduler.schedule(
                repositories,
                task_id,
                artifact_id=report_artifact_id,
                version_id=report_version_id,
                parent_version_id=source_version["id"],
                report_format=body.format,
            )

    @app.post("/api/findings/{finding_id}/proof", status_code=202)
    async def create_proof_job(
        finding_id: str,
        body: CreateProofJobBody,
        _: Annotated[str, Depends(require_write)],
    ) -> Job:
        job_id = f"job:proof:{uuid4().hex}"
        request = cast(ProofRequest, {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": f"proof:{uuid4().hex}",
            "job_id": job_id,
            "finding_id": finding_id,
            "script_ref": body.script_ref,
            "image_digest": body.image_digest,
            "permission_mode": body.permission_mode,
            "resource_budget": body.resource_budget.model_dump(mode="json"),
            "timeout_seconds": body.resource_budget.timeout_seconds,
        })
        validate_contract("ProofRequest", request)
        scheduler = ProofJobScheduler(
            tool=ToolIdentity(name="proof-tool", version="1.0.0", image_digest=body.image_digest)
        )
        async with database.transaction() as repositories:
            return await scheduler.schedule(
                repositories,
                request,
                kind=PocKind.EXPLOIT if body.kind == "exploit" else PocKind.PROOF_OF_CONCEPT,
            )

    @app.get("/api/findings/{finding_id}/evidence")
    async def finding_evidence(
        finding_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[FindingEvidenceDetail]:
        async with database.transaction() as repositories:
            await repositories.findings.get(finding_id)
            relations = await repositories.findings.list_evidence_relations(finding_id)
            return [
                FindingEvidenceDetail(
                    relation=relation,
                    evidence=await repositories.evidence.get(relation["evidence_id"]),
                )
                for relation in relations
            ]

    @app.get("/api/findings/{finding_id}/pocs")
    async def finding_pocs(
        finding_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[Poc]:
        async with database.transaction() as repositories:
            await repositories.findings.get(finding_id)
            return await repositories.pocs.list_for_finding(finding_id)

    @app.get("/api/tasks/{task_id}/annotations")
    async def task_annotations(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[Annotation]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            return await repositories.annotations.list_for_task(task_id)

    @app.post("/api/tasks/{task_id}/annotations", status_code=201)
    async def create_annotation(
        task_id: str,
        body: CreateAnnotationBody,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    ) -> Annotation:
        key = normalize_idempotency_key(idempotency_key)
        payload = body.model_dump(mode="json")
        labels = sorted(set(body.labels))
        if not labels and not body.note and body.severity_override is None:
            raise ApiInputError(
                "empty_annotation",
                "annotation requires a label, note, or severity override",
                "body",
            )
        fingerprint = request_fingerprint({"task_id": task_id, **payload, "labels": labels})
        scope = f"tasks:{task_id}:annotations:create"
        async with database.transaction() as repositories:
            await repositories.api_requests.lock(scope=scope, key=key)
            prior = await repositories.api_requests.get(scope=scope, key=key)
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different annotation"
                    )
                response.status_code = prior.response_status
                return await repositories.annotations.get(prior.resource_id)
            annotation = Annotation(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=_identifier("annotation"),
                task_id=task_id,
                target_kind=body.target_kind,
                target_id=body.target_id,
                labels=labels,
                note=body.note,
                severity_override=body.severity_override,
                author_id=_personal_author_id("personal"),
                supersedes_annotation_id=body.supersedes_annotation_id,
                created_at=_now(),
            )
            validate_contract("Annotation", annotation)
            created = await repositories.annotations.create(annotation)
            await repositories.api_requests.add(
                scope=scope,
                key=key,
                fingerprint=fingerprint,
                resource_type="annotation",
                resource_id=created.value["id"],
                response_status=201,
            )
            return created.value

    @app.patch("/api/findings/{finding_id}/review", status_code=201)
    async def review_finding(
        finding_id: str,
        body: ReviewFindingBody,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
    ) -> Review:
        key = normalize_idempotency_key(idempotency_key)
        payload = body.model_dump(mode="json")
        fingerprint = request_fingerprint({"finding_id": finding_id, **payload})
        scope = f"findings:{finding_id}:review"
        async with database.transaction() as repositories:
            await repositories.api_requests.lock(scope=scope, key=key)
            prior = await repositories.api_requests.get(scope=scope, key=key)
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different review"
                    )
                response.status_code = prior.response_status
                return await repositories.findings.get_review(prior.resource_id)
            if body.supersedes_review_id is not None:
                superseded = await repositories.findings.get_review(
                    body.supersedes_review_id
                )
                if superseded["finding_id"] != finding_id:
                    raise ApiInputError(
                        "review_history_mismatch",
                        "review may only supersede history for the same finding",
                        "supersedes_review_id",
                    )
            review = Review(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=_identifier("review"),
                finding_id=finding_id,
                outcome=body.outcome,
                rationale=body.rationale,
                model=f"human:{_personal_author_id('personal')}",
                supersedes_review_id=body.supersedes_review_id,
                created_at=_now(),
            )
            validate_contract("Review", review)
            result = await review_gate.submit_in_transaction(repositories, review)
            if not result.persisted:
                reasons = result.decision.reason_codes if result.decision else ()
                raise ApiInputError(
                    "confirmation_policy_denied",
                    "finding confirmation lacks required evidence: " + ", ".join(reasons),
                    "outcome",
                )
            await repositories.api_requests.add(
                scope=scope,
                key=key,
                fingerprint=fingerprint,
                resource_type="review",
                resource_id=review["id"],
                response_status=201,
            )
            return review

    @app.get("/api/tasks/{task_id}/events")
    async def task_events(
        task_id: str, after: int = -1, _: Annotated[str, Depends(require_account)] = ""
    ) -> list[QueueEvent]:
        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            return await repositories.task_events.list_after(task_id, after_sequence=after)

    @app.websocket("/api/tasks/{task_id}/events/ws")
    async def task_events_ws(websocket: WebSocket, task_id: str, after: int = -1) -> None:
        try:
            await auth.authenticate(websocket.cookies.get(SESSION_COOKIE))
        except (AuthenticationFailed, PasswordChangeRequired):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        cursor = after
        disconnected = asyncio.create_task(_wait_for_websocket_disconnect(websocket))
        try:
            while not disconnected.done():
                async with database.transaction() as repositories:
                    await repositories.tasks.get(task_id)
                    events = await repositories.task_events.list_after(
                        task_id, after_sequence=cursor
                    )
                for event in events:
                    if disconnected.done():
                        return
                    await websocket.send_json(event)
                    cursor = max(cursor, event["sequence"])
                done, _ = await asyncio.wait({disconnected}, timeout=0.5)
                if done:
                    await disconnected
                    return
        except WebSocketDisconnect:
            return
        except Exception:
            if disconnected.done():
                return
            LOGGER.exception("task event WebSocket failed", extra={"task_id": task_id})
            with suppress(RuntimeError):
                await websocket.close(code=1011)
        finally:
            disconnected.cancel()
            await asyncio.gather(disconnected, return_exceptions=True)

    return app


async def _wait_for_websocket_disconnect(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return


async def _artifact_detail(repositories: Any, project_id: str, artifact_id: str) -> ArtifactDetail:
    artifact = await repositories.artifacts.get(artifact_id)
    if artifact["project_id"] != project_id:
        raise ApiInputError(
            "artifact_project_mismatch", "artifact does not belong to this project", "artifact_id"
        )
    versions = await repositories.artifacts.list_versions(artifact_id)
    return ArtifactDetail(
        artifact=cast(Artifact, dict(artifact)),
        versions=[cast(ArtifactVersion, dict(version)) for version in versions],
    )


def _validate_upload_kind(kind: ArtifactKind) -> None:
    if kind in {ArtifactKind.DERIVED, ArtifactKind.SOURCE_REPOSITORY}:
        raise ApiInputError(
            "unsupported_upload_kind",
            "direct upload accepts source archives, ELF, or PE only",
            "kind",
        )


def _matches_declared_format(kind: ArtifactKind, head: bytes) -> bool:
    if kind is ArtifactKind.ELF:
        return head.startswith(b"\x7fELF")
    if kind is ArtifactKind.PE:
        return head.startswith(b"MZ")
    return head.startswith((b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")) or (
        len(head) > 262 and head[257:262] == b"ustar"
    )


def _identifier(prefix: str) -> str:
    return f"{prefix}:{uuid4().hex}"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _personal_author_id(username: str) -> str:
    return "account:" + hashlib.sha256(username.encode()).hexdigest()[:24]


def _product_settings_response(values: dict[str, object]) -> ProductSettingsResponse:
    public_values = {
        key: value for key, value in values.items() if key != "review_model_api_key"
    }
    parsed = ProductSettingsBody.model_validate(
        {"schema_version": "1.0.0", **public_values}
    )
    return ProductSettingsResponse(
        review_model_base_url=parsed.review_model_base_url,
        review_model_name=parsed.review_model_name,
        review_model_timeout_seconds=parsed.review_model_timeout_seconds,
        review_model_max_attempts=parsed.review_model_max_attempts,
        review_model_repair_attempts=parsed.review_model_repair_attempts,
        review_model_min_interval_seconds=parsed.review_model_min_interval_seconds,
        api_key_configured="review_model_api_key" in values,
    )


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts
