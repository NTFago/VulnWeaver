"""FastAPI application for projects, artifacts, tasks, and task events."""
# pyright: reportUnusedFunction=false

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import uuid4

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from vulnweaver_artifact_store import ArtifactStoreError, LocalContentAddressedStore
from vulnweaver_contracts import (
    Artifact,
    ArtifactKind,
    ArtifactVersion,
    ContractValidationError,
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    Project,
    QueueEvent,
    ResourceBudget,
    RetryPolicy,
    SchemaVersion,
    Task,
    TaskStatus,
    TaskStatusChangedEvent,
    validate_contract,
)
from vulnweaver_domain import normalize_idempotency_key
from vulnweaver_persistence import Database, DatabaseSettings, IdempotencyConflict, PersistenceError
from vulnweaver_persistence.fingerprints import request_fingerprint

from vulnweaver_api.auth import (
    SESSION_COOKIE,
    AuthenticationFailed,
    PasswordChangeRequired,
    PersonalAuthService,
)
from vulnweaver_api.schemas import (
    ArtifactDetail,
    CreateProjectBody,
    CreateTaskBody,
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
)
from vulnweaver_api.settings import ApiSettings

IDEMPOTENCY_HEADER = Header(alias="Idempotency-Key", min_length=8, max_length=128)
CSRF_HEADER = Header(alias="X-CSRF-Token", min_length=8, max_length=256)


def create_app(settings: ApiSettings | None = None) -> FastAPI:
    configuration = settings or ApiSettings.from_env()
    database = Database(DatabaseSettings(configuration.database_url))
    store = LocalContentAddressedStore(configuration.artifact_store_root)
    auth = PersonalAuthService(database, session_ttl_seconds=configuration.session_ttl_seconds)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if configuration.bootstrap_password_file is not None:
            password = _read_password_file(configuration.bootstrap_password_file)
            await auth.bootstrap(configuration.personal_username, password)
        yield
        await database.dispose()

    app = FastAPI(
        title="VulnWeaver API",
        version="1.0.0",
        lifespan=lifespan,
        responses={
            400: {"model": ErrorResponse},
            401: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
        },
    )
    app.state.database = database
    app.state.store = store
    app.state.auth = auth
    app.state.settings = configuration

    @app.middleware("http")
    async def correlation_middleware(request: Request, call_next: Any) -> Response:
        supplied = request.headers.get("X-Correlation-ID", "")
        correlation_id = supplied if _valid_identifier(supplied) else _identifier("request")
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    _install_error_handlers(app)

    async def require_account(
        request: Request,
        session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    ) -> str:
        await auth.authenticate(session)
        request.state.session_token = session
        assert session is not None
        return session

    async def require_write(
        request: Request,
        session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
        csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    ) -> str:
        await auth.authenticate(session)
        assert session is not None
        await auth.verify_csrf(session, csrf_token)
        request.state.session_token = session
        return session

    @app.post("/api/auth/login", response_model=MeResponse)
    async def login(body: LoginRequest, response: Response) -> MeResponse:
        result = await auth.login(body.username, body.password)
        response.set_cookie(
            SESSION_COOKIE,
            result.token,
            httponly=True,
            secure=configuration.secure_cookie,
            samesite="strict",
            max_age=configuration.session_ttl_seconds,
            path="/",
        )
        response.headers["X-CSRF-Token"] = result.csrf_token
        return MeResponse(
            username=result.account.username,
            must_change_password=result.account.must_change_password,
        )

    @app.get("/api/auth/me", response_model=MeResponse)
    async def me(session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None) -> MeResponse:
        account = await auth.authenticate(session, allow_password_change=True)
        return MeResponse(
            username=account.username, must_change_password=account.must_change_password
        )

    @app.post("/api/auth/logout", status_code=204)
    async def logout(
        response: Response,
        session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
        csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    ) -> None:
        await auth.authenticate(session, allow_password_change=True)
        assert session is not None
        await auth.verify_csrf(session, csrf_token)
        await auth.logout(session)
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=configuration.secure_cookie,
            httponly=True,
            samesite="strict",
        )

    @app.post("/api/auth/password", status_code=204)
    async def change_password(
        body: PasswordChangeRequest,
        response: Response,
        session: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
        csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
    ) -> None:
        await auth.authenticate(session, allow_password_change=True)
        assert session is not None
        await auth.verify_csrf(session, csrf_token)
        await auth.change_password(session, body.current_password, body.new_password)
        response.delete_cookie(
            SESSION_COOKIE,
            path="/",
            secure=configuration.secure_cookie,
            httponly=True,
            samesite="strict",
        )

    @app.get("/health/live", response_model=HealthResponse)
    async def live() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.get("/health/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        await database.healthcheck()
        async with database.transaction() as repositories:
            account = await repositories.personal_auth.account()
        if account is None:
            raise HTTPException(status_code=503, detail="personal account is not initialized")
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
        "/api/projects/{project_id}/artifacts", response_model=ArtifactDetail, status_code=201
    )
    async def upload_artifact(
        project_id: str,
        response: Response,
        _: Annotated[str, Depends(require_write)],
        idempotency_key: Annotated[str, IDEMPOTENCY_HEADER],
        kind: Annotated[ArtifactKind, Form()],
        file: Annotated[UploadFile, File()],
    ) -> ArtifactDetail:
        key = normalize_idempotency_key(idempotency_key)
        _validate_upload_kind(kind)
        head = await file.read(512)
        await file.seek(0)
        if not head:
            raise ApiInputError("empty_artifact", "uploaded artifact must not be empty", "file")
        if not _matches_declared_format(kind, head):
            raise ApiInputError(
                "artifact_format_mismatch",
                "content does not match the declared artifact kind",
                "kind",
            )
        stored = await asyncio.to_thread(
            store.put_stream, file.file, max_bytes=configuration.upload_max_bytes
        )
        fingerprint = request_fingerprint({"kind": str(kind), "digest": stored.digest})
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)
            scope = f"projects:{project_id}:artifacts:create"
            await repositories.api_requests.lock(scope=scope, key=key)
            prior = await repositories.api_requests.get(scope=scope, key=key)
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different upload"
                    )
                response.status_code = prior.response_status
                return await _artifact_detail(repositories, project_id, prior.resource_id)
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
                generation_config={"filename": file.filename or "upload"},
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
            return ArtifactDetail(artifact=dict(artifact), versions=[dict(version)])

    @app.get("/api/projects/{project_id}/artifacts/{artifact_id}", response_model=ArtifactDetail)
    async def get_artifact(
        project_id: str, artifact_id: str, _: Annotated[str, Depends(require_account)]
    ) -> ArtifactDetail:
        async with database.transaction() as repositories:
            return await _artifact_detail(repositories, project_id, artifact_id)

    @app.get("/api/artifacts/{artifact_id}/content")
    async def artifact_content(
        artifact_id: str, _: Annotated[str, Depends(require_account)]
    ) -> StreamingResponse:
        async with database.transaction() as repositories:
            artifact = await repositories.artifacts.get(artifact_id)
            version = await repositories.artifacts.get_version(artifact["current_version_id"])

        def chunks():
            with store.open(version["object_ref"]) as stream:
                while chunk := stream.read(1024 * 1024):
                    yield chunk

        return StreamingResponse(
            chunks(), media_type="application/octet-stream", headers={"ETag": version["digest"]}
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
            status=TaskStatus.VALIDATING,
            result=None,
            idempotency_key=key,
            resource_budget=cast(ResourceBudget, payload["resource_budget"]),
            created_at=now,
            updated_at=now,
        )
        async with database.transaction() as repositories:
            await repositories.projects.get(project_id)
            input_refs: list[str] = []
            for version_id in task["artifact_version_ids"]:
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                if artifact["project_id"] != project_id:
                    raise ApiInputError(
                        "artifact_project_mismatch",
                        "artifact version does not belong to this project",
                        "artifact_version_ids",
                    )
                input_refs.append(version["object_ref"])
            result = await repositories.tasks.create(task)
            if not result.created:
                response.status_code = 200
                return result.value
            job = _validation_job(result.value, input_refs, now)
            job_event = _job_requested(job, now)
            task_event = _task_started(result.value, now)
            await repositories.jobs.enqueue_with_outbox(job, job_event)
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
            current = await repositories.tasks.get(task_id)
            task = await repositories.tasks.cancel(task_id)
            await repositories.jobs.cancel_for_task(task_id)
            if (
                task["status"] is TaskStatus.CANCELLED
                and current["status"] is not TaskStatus.CANCELLED
            ):
                sequence = await repositories.task_events.next_sequence(task_id)
                event = _task_cancelled(task, current["status"], sequence)
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
        try:
            while True:
                async with database.transaction() as repositories:
                    await repositories.tasks.get(task_id)
                    events = await repositories.task_events.list_after(
                        task_id, after_sequence=cursor
                    )
                for event in events:
                    await websocket.send_json(event)
                    cursor = max(cursor, event["sequence"])
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return
        except Exception:
            await websocket.close(code=1011)

    return app


class ApiInputError(ValueError):
    def __init__(self, code: str, message: str, field: str) -> None:
        self.code = code
        self.message = message
        self.field = field
        super().__init__(message)


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        details = [
            ErrorDetail(field=".".join(str(part) for part in item["loc"]), reason=item["msg"])
            for item in error.errors()
        ]
        return _error(
            request, 422, "request_validation_failed", "request validation failed", details=details
        )

    @app.exception_handler(ContractValidationError)
    async def contract_error(request: Request, error: ContractValidationError) -> JSONResponse:
        return _error(
            request,
            422,
            "contract_validation_failed",
            "request does not satisfy the public contract",
            details=[ErrorDetail(field=error.definition, reason=item) for item in error.errors],
        )

    @app.exception_handler(ApiInputError)
    async def input_error(request: Request, error: ApiInputError) -> JSONResponse:
        return _error(
            request,
            422,
            error.code,
            error.message,
            details=[ErrorDetail(field=error.field, reason=error.message)],
        )

    @app.exception_handler(AuthenticationFailed)
    async def auth_error(request: Request, error: AuthenticationFailed) -> JSONResponse:
        return _error(request, 401, "authentication_failed", str(error))

    @app.exception_handler(PasswordChangeRequired)
    async def password_change_error(
        request: Request, error: PasswordChangeRequired
    ) -> JSONResponse:
        return _error(request, 403, "password_change_required", str(error))

    @app.exception_handler(ValueError)
    async def value_error(request: Request, error: ValueError) -> JSONResponse:
        return _error(request, 422, "invalid_request", str(error))

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        message = error.detail
        return _error(request, error.status_code, "http_error", message)

    @app.exception_handler(PersistenceError)
    async def persistence_error(request: Request, error: PersistenceError) -> JSONResponse:
        status = (
            404
            if error.code == "entity_not_found"
            else 409
            if error.code in {"entity_conflict", "idempotency_conflict"}
            else 500
        )
        details = [
            ErrorDetail(field=str(key), reason=str(value)) for key, value in error.details.items()
        ]
        return _error(
            request, status, error.code, error.message, retryable=error.retryable, details=details
        )

    @app.exception_handler(ArtifactStoreError)
    async def artifact_error(request: Request, error: ArtifactStoreError) -> JSONResponse:
        status = (
            413
            if error.code == "artifact_too_large"
            else 404
            if error.code == "artifact_not_found"
            else 422
        )
        return _error(request, status, error.code, error.message, retryable=error.retryable)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, _: Exception) -> JSONResponse:
        return _error(request, 500, "internal_error", "an unexpected internal error occurred")


def _error(
    request: Request,
    status: int,
    code: str,
    message: str,
    *,
    retryable: bool = False,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", _identifier("request"))
    body = ErrorResponse(
        error_code=code,
        message=message,
        correlation_id=correlation_id,
        retryable=retryable,
        details=details or [],
    )
    return JSONResponse(
        status_code=status,
        content=body.model_dump(mode="json"),
        headers={"X-Correlation-ID": correlation_id},
    )


async def _artifact_detail(repositories: Any, project_id: str, artifact_id: str) -> ArtifactDetail:
    artifact = await repositories.artifacts.get(artifact_id)
    if artifact["project_id"] != project_id:
        raise ApiInputError(
            "artifact_project_mismatch", "artifact does not belong to this project", "artifact_id"
        )
    versions = await repositories.artifacts.list_versions(artifact_id)
    return ArtifactDetail(artifact=dict(artifact), versions=[dict(version) for version in versions])


def _validation_job(task: Task, input_refs: list[str], now: str) -> Job:
    return Job(
        schema_version=SchemaVersion.VALUE_1_0_0,
        id=_identifier("job"),
        task_id=task["id"],
        kind=JobKind.VALIDATE,
        input_refs=input_refs,
        status=JobStatus.PENDING,
        idempotency_key=f"validate:{task['id']}",
        resource_budget=task["resource_budget"],
        retry_policy=cast(
            RetryPolicy,
            {
                "max_attempts": 2,
                "backoff_seconds": 1.0,
                "retryable_failure_kinds": [FailureKind.ENVIRONMENT, FailureKind.DEPENDENCY],
            },
        ),
        attempt=0,
        lease=None,
        failure=None,
        created_at=now,
        updated_at=now,
    )


def _job_requested(job: Job, now: str) -> JobRequestedEvent:
    return JobRequestedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_identifier("event"),
        event_type="job.requested",
        aggregate_id=job["id"],
        sequence=0,
        occurred_at=now,
        correlation_id=job["task_id"],
        causation_id=None,
        payload={
            "job_id": job["id"],
            "task_id": job["task_id"],
            "job_kind": job["kind"],
            "attempt": 0,
        },
    )


def _task_started(task: Task, now: str) -> TaskStatusChangedEvent:
    return TaskStatusChangedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_identifier("event"),
        event_type="task.status_changed",
        aggregate_id=task["id"],
        sequence=0,
        occurred_at=now,
        correlation_id=task["id"],
        causation_id=None,
        payload={
            "task_id": task["id"],
            "previous_status": TaskStatus.CREATED,
            "status": TaskStatus.VALIDATING,
            "result": None,
        },
    )


def _task_cancelled(
    task: Task, previous_status: TaskStatus, sequence: int
) -> TaskStatusChangedEvent:
    now = _now()
    return TaskStatusChangedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_identifier("event"),
        event_type="task.status_changed",
        aggregate_id=task["id"],
        sequence=sequence,
        occurred_at=now,
        correlation_id=task["id"],
        causation_id=None,
        payload={
            "task_id": task["id"],
            "previous_status": previous_status,
            "status": TaskStatus.CANCELLED,
            "result": None,
        },
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


def _valid_identifier(value: str) -> bool:
    return (
        1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _read_password_file(path: Path) -> str:
    resolved = path.expanduser().resolve(strict=True)
    if resolved.stat().st_size > 4096:
        raise ValueError("personal password file is too large")
    password = resolved.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise ValueError("personal password file is empty")
    return password
