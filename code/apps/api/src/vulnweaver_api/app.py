"""FastAPI application for projects, artifacts, tasks, and task events."""
# pyright: reportUnusedFunction=false

import asyncio
import hashlib
import logging
from collections.abc import Iterable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Annotated, Any, cast
from urllib.parse import quote, urlparse
from uuid import uuid4

import httpx
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
from vulnweaver_orchestrator.code_audit import AUDIT_CHECKPOINT_NODE
from vulnweaver_persistence import (
    Database,
    DatabaseSettings,
    EntityNotFound,
    IdempotencyConflict,
    Repositories,
)
from vulnweaver_persistence.fingerprints import request_fingerprint
from vulnweaver_proof import ProofJobScheduler
from vulnweaver_reporting import ReportJobScheduler

from vulnweaver_api.audit_trail import build_audit_trail
from vulnweaver_api.auth import (
    SESSION_COOKIE,
    AuthenticationFailed,
    PasswordChangeRequired,
    PersonalAuthService,
)
from vulnweaver_api.budgets import resolve_project_budget
from vulnweaver_api.cookies import delete_session_cookies, set_session_cookies
from vulnweaver_api.errors import ApiInputError, install_error_handlers
from vulnweaver_api.events import task_cancelled, task_requested
from vulnweaver_api.middleware import CorrelationIdMiddleware, RequestBodyLimitMiddleware
from vulnweaver_api.schemas import (
    ActivityAuditProgress,
    ActivityJobSummary,
    ActivityRunSummary,
    ArtifactDetail,
    AuditTrailResponse,
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
    ModelProbeBody,
    ModelProbeResponse,
    PairFunctionPage,
    PasswordChangeRequest,
    ProductSettingsBody,
    ProductSettingsResponse,
    RegistrationRequest,
    ReviewFindingBody,
    SessionResponse,
    TaskActivityResponse,
)
from vulnweaver_api.settings import ApiSettings
from vulnweaver_api.uploads import remove_stale_uploads, stage_upload

LOGGER = logging.getLogger(__name__)
IDEMPOTENCY_HEADER = Header(alias="Idempotency-Key", min_length=8, max_length=128)
_TIER_NAMES = ("planning", "audit", "review", "report")
CSRF_HEADER = Header(alias="X-CSRF-Token", min_length=8, max_length=256)
# Attributes the workbench list renders; everything else (pseudocode bodies,
# parameters, raw ids) is only needed for the selected function's detail.
_PAIR_LIST_ATTRIBUTE_KEYS = ("critical_logic",)


def _pair_list_projection(function: PairFunction) -> PairFunction:
    attributes = function["attributes"]
    return cast(
        PairFunction,
        {
            **function,
            "attributes": {
                key: attributes[key] for key in _PAIR_LIST_ATTRIBUTE_KEYS if key in attributes
            },
        },
    )


async def _pair_scopes(repositories: Repositories, task: Task) -> list[str]:
    """Return the artifact versions a task's PAIR functions belong to.

    The two pipelines scope differently.  Source functions are keyed to the
    artifact version the task imported; binary functions are keyed to the image
    the analysis actually read -- the unpacked one when the input was packed --
    which is the parent of the task's ``binary-analysis-result`` version, as
    recorded among the binary-import Job's outputs.  The workbench serves both,
    so it queries both.
    """

    resolved: list[str] = list(task["artifact_version_ids"])
    for job in await repositories.jobs.list_for_task(task["id"]):
        if (job.get("tool") or {}).get("name") != "binary-import":
            continue
        result = await repositories.jobs.get_result(job["id"])
        if result is None:
            continue
        for version_id in result["produced_artifact_version_ids"]:
            version = await repositories.artifacts.get_version(version_id)
            config = version.get("generation_config") or {}
            if config.get("format") != "binary-analysis-result":
                continue
            parent = version.get("parent_version_id")
            if isinstance(parent, str) and parent and parent not in resolved:
                resolved.append(parent)
    return resolved


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
                "tier_api_keys",
                "clear_tier_api_keys",
                "provider_api_keys",
                "clear_provider_api_keys",
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
        for tier_name, tier in values["model_tiers"].items():
            tier_base_url = str(tier["base_url"]).strip().rstrip("/")
            tier_model = str(tier["model_name"]).strip()
            if bool(tier_base_url) != bool(tier_model):
                raise ApiInputError(
                    "incomplete_model_configuration",
                    "model endpoint and model name must be configured together",
                    f"model_tiers.{tier_name}",
                )
            if tier_base_url and not tier_base_url.startswith(("https://", "http://")):
                raise ApiInputError(
                    "invalid_model_endpoint",
                    "model endpoint must use HTTP or HTTPS",
                    f"model_tiers.{tier_name}.base_url",
                )
            if (
                tier["thinking_mode"] == "custom"
                and int(tier["thinking_budget_tokens"] or 0) < 1024
            ):
                raise ApiInputError(
                    "invalid_thinking_budget",
                    "custom thinking mode requires a budget of at least 1024 tokens",
                    f"model_tiers.{tier_name}.thinking_budget_tokens",
                )
            tier["base_url"] = tier_base_url
            tier["model_name"] = tier_model
        values["review_model_base_url"] = base_url
        values["review_model_name"] = model_name
        _validate_model_providers(body)
        async with database.transaction() as repositories:
            previous = await repositories.product_settings.get()
            stored_key = previous.get("review_model_api_key")
            if body.clear_review_model_api_key:
                stored_key = None
            elif body.review_model_api_key is not None:
                stored_key = body.review_model_api_key
            if stored_key is not None:
                values["review_model_api_key"] = stored_key
            previous_tier_keys = cast(
                dict[str, object], previous.get("tier_api_keys") or {}
            )
            tier_keys: dict[str, object] = {
                key: value
                for key, value in previous_tier_keys.items()
                if key in _TIER_NAMES and key not in body.clear_tier_api_keys
            }
            for tier_name in _TIER_NAMES:
                supplied = getattr(body.tier_api_keys, tier_name)
                if supplied is not None:
                    tier_keys[tier_name] = supplied
            if tier_keys:
                values["tier_api_keys"] = tier_keys
            provider_keys = _merge_provider_api_keys(body, previous)
            if provider_keys:
                values["provider_api_keys"] = provider_keys
            await repositories.product_settings.replace(values)
        return _product_settings_response(values)

    @app.post("/api/settings/model-probe", response_model=ModelProbeResponse)
    async def probe_provider_models(
        body: ModelProbeBody,
        _: Annotated[str, Depends(require_write)],
    ) -> ModelProbeResponse:
        """Fetch a provider's live model list for the settings "smart config"."""

        base_url = body.base_url.strip().rstrip("/")
        stored_providers: dict[str, object] = {}
        stored_keys: dict[str, object] = {}
        async with database.transaction() as repositories:
            stored = await repositories.product_settings.get()
            raw_providers = stored.get("model_providers")
            if isinstance(raw_providers, list):
                for entry in cast(list[object], raw_providers):
                    if isinstance(entry, dict):
                        entry_fields = cast(dict[str, object], entry)
                        entry_id = entry_fields.get("id")
                        if isinstance(entry_id, str):
                            stored_providers[entry_id] = entry_fields
            raw_keys = stored.get("provider_api_keys")
            if isinstance(raw_keys, dict):
                stored_keys = cast(dict[str, object], raw_keys)
        provider_entry = (
            stored_providers.get(body.provider_id or "")
            if body.provider_id
            else None
        )
        if isinstance(provider_entry, dict) and not base_url:
            candidate = cast(dict[str, object], provider_entry).get("base_url")
            if isinstance(candidate, str):
                base_url = candidate.strip().rstrip("/")
        if not base_url:
            raise ApiInputError(
                "incomplete_model_configuration",
                "a base URL is required to probe models",
                "base_url",
            )
        if not base_url.startswith(("https://", "http://")):
            raise ApiInputError(
                "invalid_model_endpoint",
                "model endpoint must use HTTP or HTTPS",
                "base_url",
            )
        api_key = body.api_key
        if api_key is None and body.provider_id:
            stored_value = stored_keys.get(body.provider_id)
            if isinstance(stored_value, str):
                api_key = stored_value
        try:
            models = await _probe_model_list(base_url, body.api_format, api_key)
        except ModelProbeError as error:
            return ModelProbeResponse(models=[], error=error.message)
        return ModelProbeResponse(models=models)

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
        # An omitted budget stays omitted in the contract payload; the stored row is
        # resolved server-side because budgets are inert bookkeeping (ADR-025).
        payload = body.model_dump(mode="json", exclude_none=True)
        validate_contract("CreateProjectRequest", payload)
        payload["resource_budget"] = resolve_project_budget()
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

    @app.delete("/api/projects/{project_id}", status_code=204)
    async def delete_project(
        project_id: str, _: Annotated[str, Depends(require_write)]
    ) -> Response:
        async with database.transaction() as repositories:
            await repositories.deletion.delete_project(project_id)
        return Response(status_code=204)

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
                    "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
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
        filename: Annotated[str | None, Header(alias="X-Artifact-Filename", max_length=512)] = None,
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
                raise ApiInputError("empty_artifact", "uploaded artifact must not be empty", "body")
            if not _matches_declared_format(kind, staged.head):
                raise ApiInputError(
                    "artifact_format_mismatch",
                    "content does not match the declared artifact kind",
                    "kind",
                )
            fingerprint = request_fingerprint({"kind": str(kind), "digest": staged.digest})
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
                    return await _artifact_detail(repositories, project_id, prior.resource_id)
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

        media_type, filename = _artifact_download_metadata(version)
        return StreamingResponse(
            chunks(),
            media_type=media_type,
            headers={
                "ETag": f'"{version["digest"]}"',
                "Content-Disposition": _content_disposition(filename),
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
            },
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
        payload = body.model_dump(mode="json", exclude_none=True)
        validate_contract("CreateTaskRequest", payload)
        now = _now()
        async with database.transaction() as repositories:
            project = await repositories.projects.get(project_id)
            for version_id in payload["artifact_version_ids"]:
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                if artifact["project_id"] != project_id:
                    raise ApiInputError(
                        "artifact_project_mismatch",
                        "artifact version does not belong to this project",
                        "artifact_version_ids",
                    )
            task = Task(
                schema_version=SchemaVersion.VALUE_1_0_0,
                id=_identifier("task"),
                project_id=project_id,
                artifact_version_ids=payload["artifact_version_ids"],
                status=TaskStatus.CREATED,
                result=None,
                failure=None,
                idempotency_key=key,
                # Omitted budgets inherit the project row; budgets are inert bookkeeping.
                resource_budget=cast(
                    ResourceBudget, payload.get("resource_budget") or project["resource_budget"]
                ),
                created_at=now,
                updated_at=now,
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

    @app.delete("/api/tasks/{task_id}", status_code=204)
    async def delete_task(task_id: str, _: Annotated[str, Depends(require_write)]) -> Response:
        async with database.transaction() as repositories:
            await repositories.deletion.delete_task(task_id)
        return Response(status_code=204)

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

    @app.get("/api/tasks/{task_id}/activity", response_model=TaskActivityResponse)
    async def task_activity(
        task_id: str,
        after: int = -1,
        _: Annotated[str, Depends(require_account)] = "",
    ) -> TaskActivityResponse:
        """One lightweight liveness snapshot for the task view's periodic poll.

        Long investigations have no task-status transitions for long stretches,
        so this endpoint surfaces the signals that do change while work runs:
        job lease heartbeats, the newest agent decision per run, and the audit
        loop's checkpoint (rounds and investigation journal).  Events ride the
        same response so one request replaces the previous polling storm.
        """
        if after < -1:
            raise ApiInputError(
                "invalid_event_cursor", "event cursor must be >= -1", "after"
            )
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            jobs = await repositories.jobs.list_for_task(task_id)
            runs = await repositories.agent_runs.summarize_for_task(task_id)
            checkpoint = await repositories.checkpoints.latest_for_node(
                task_id, AUDIT_CHECKPOINT_NODE
            )
            events = await repositories.task_events.list_after(task_id, after_sequence=after)

        job_summaries = [
            ActivityJobSummary.model_validate(
                {
                    "id": job["id"],
                    "kind": str(job["kind"]),
                    "tool_name": (job.get("tool") or {}).get("name"),
                    "status": str(job["status"]),
                    "attempt": job["attempt"],
                    "created_at": job["created_at"],
                    "updated_at": job["updated_at"],
                    "lease_expires_at": (job.get("lease") or {}).get("expires_at"),
                    "failure_code": (job.get("failure") or {}).get("code"),
                }
            )
            for job in jobs
        ]
        run_summaries = [
            ActivityRunSummary.model_validate(
                {
                    "id": run["id"],
                    "status": str(run["status"]),
                    "model": run["model"],
                    "created_at": run["created_at"],
                    "updated_at": run["updated_at"],
                    "duration_ms": run["duration_ms"],
                    "decision_count": run["decision_count"],
                    "latest_decision": run["latest_decision"],
                    "latest_decision_reason": run["latest_decision_reason"],
                    "latest_decision_at": run["latest_decision_at"],
                    "input_tokens": run["token_usage"].get("input_tokens"),
                    "output_tokens": run["token_usage"].get("output_tokens"),
                    "failure_code": (run["failure"] or {}).get("code"),
                }
            )
            for run in runs
        ]
        progress: ActivityAuditProgress | None = None
        if checkpoint is not None:
            state = checkpoint.state
            usage_raw = state.get("usage")
            usage_dict = cast("dict[str, object]", usage_raw) if isinstance(usage_raw, dict) else {}
            journal_raw = state.get("journal")
            journal = cast("list[object]", journal_raw) if isinstance(journal_raw, list) else []
            progress = ActivityAuditProgress.model_validate(
                {
                    "rounds": state.get("rounds", 0),
                    "completed": bool(state.get("completed", False)),
                    "model_label": state.get("model_label"),
                    "updated_at": _format_api_datetime(checkpoint.created_at),
                    "input_tokens": usage_dict.get("input_tokens"),
                    "output_tokens": usage_dict.get("output_tokens"),
                    "journal_tail": cast(
                        "list[dict[str, Any]]", journal[-5:]
                    ),
                }
            )
        timestamps = [task["updated_at"], *(job["updated_at"] for job in jobs)]
        timestamps.extend(run.updated_at for run in run_summaries)
        if checkpoint is not None:
            timestamps.append(_format_api_datetime(checkpoint.created_at))
        return TaskActivityResponse.model_validate(
            {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "task_status": str(task["status"]),
                "task_updated_at": task["updated_at"],
                "jobs": job_summaries,
                "runs": run_summaries,
                "audit_progress": progress,
                "latest_activity_at": max(timestamps) if timestamps else None,
                "events": [dict(event) for event in events],
            }
        )

    @app.get("/api/tasks/{task_id}/audit-trail", response_model=AuditTrailResponse)
    async def task_audit_trail(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> AuditTrailResponse:
        """Project durable audit facts without changing AgentRun or Job records."""

        async with database.transaction() as repositories:
            await repositories.tasks.get(task_id)
            runs = await repositories.agent_runs.list_for_task(task_id)
            jobs = await repositories.jobs.list_for_task(task_id)
            results = await repositories.jobs.get_results([job["id"] for job in jobs])
        return AuditTrailResponse.model_validate(
            build_audit_trail(task_id=task_id, runs=runs, jobs=jobs, results=results)
        )

    @app.get("/api/tasks/{task_id}/pair")
    async def task_pair(
        task_id: str, _: Annotated[str, Depends(require_account)]
    ) -> list[PairFunction]:
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            functions: list[PairFunction] = []
            for version_id in await _pair_scopes(repositories, task):
                functions.extend(await repositories.pair.list_functions(version_id))
            return functions

    @app.get("/api/tasks/{task_id}/pair/light", response_model=PairFunctionPage)
    async def task_pair_light(
        task_id: str,
        offset: int = 0,
        limit: int = 300,
        name_contains: str = "",
        _: Annotated[str, Depends(require_account)] = "",
    ) -> PairFunctionPage:
        """One bounded page of the workbench function list.

        Large trees carry tens of thousands of functions; shipping them all
        made the task view transfer tens of megabytes and proxy every row in
        browser memory.  The list is filtered and paged server-side, projected
        to the fields the list UI renders (names, locations, signatures,
        critical-logic badges) -- pseudocode and full attributes ride the
        per-function detail endpoint instead.
        """
        if offset < 0:
            raise ApiInputError("invalid_pair_offset", "offset must be >= 0", "offset")
        if not 1 <= limit <= 1000:
            raise ApiInputError("invalid_pair_limit", "limit must be between 1 and 1000", "limit")
        if len(name_contains) > 256:
            raise ApiInputError(
                "invalid_pair_query", "name filter is limited to 256 characters", "name_contains"
            )
        query = name_contains.strip()
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            scopes = await _pair_scopes(repositories, task)
            page_functions, total = await repositories.pair.list_functions_page(
                scopes, offset=offset, limit=limit, name_contains=query
            )
        projected = [_pair_list_projection(function) for function in page_functions]
        return PairFunctionPage.model_validate(
            {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "total": total,
                "offset": offset,
                "limit": limit,
                "functions": projected,
            }
        )

    @app.get("/api/tasks/{task_id}/pair/function/{function_id}")
    async def task_pair_function(
        task_id: str, function_id: str, _: Annotated[str, Depends(require_account)]
    ) -> PairFunction:
        """One full function record (including pseudocode) for the workbench detail."""
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            function = await repositories.pair.get_function(function_id)
            if function["artifact_version_id"] not in await _pair_scopes(repositories, task):
                raise ApiInputError(
                    "pair_function_not_found",
                    "pair function is not part of the task",
                    "function_id",
                )
            return function

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
            for version_id in await _pair_scopes(repositories, task):
                functions.extend(await repositories.pair.functions_at_address(version_id, address))
            return functions

    @app.get("/api/tasks/{task_id}/pair/function/{function_id}/neighborhood")
    async def task_pair_neighborhood(
        task_id: str,
        function_id: str,
        depth: int = 1,
        _: Annotated[str, Depends(require_account)] = "",
    ) -> dict[str, Any]:
        """Return bounded caller/callee edges for a function in the task.

        The matched function's neighbours are echoed back as light records so
        the UI can label caller/callee buttons without holding the whole
        function list client-side.
        """
        if depth < 1 or depth > 3:
            raise ApiInputError(
                "invalid_pair_depth", "pair neighborhood depth must be between 1 and 3", "depth"
            )
        async with database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            for version_id in await _pair_scopes(repositories, task):
                functions = await repositories.pair.list_functions(version_id)
                if any(function["id"] == function_id for function in functions):
                    neighborhood = await repositories.pair.neighborhood(
                        version_id, function_id, depth=depth
                    )
                    nodes_raw = neighborhood.get("nodes")
                    if isinstance(nodes_raw, list):
                        nodes = cast("list[dict[str, object]]", nodes_raw)
                    else:
                        nodes = []
                    related_ids = sorted(
                        {
                            related_id
                            for node in nodes
                            if isinstance(related_id := node.get("function_id"), str) and related_id
                        }
                    )
                    related = await repositories.pair.functions_by_ids(version_id, related_ids)
                    return {
                        **neighborhood,
                        "functions": [_pair_list_projection(function) for function in related],
                    }
        raise ApiInputError(
            "pair_function_not_found", "pair function is not part of the task", "function_id"
        )

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
        async with database.transaction() as repositories:
            finding = await repositories.findings.get(finding_id)
            task = await repositories.tasks.get(finding["task_id"])
            project = await repositories.projects.get(task["project_id"])
            # Budgets are inert bookkeeping (ADR-025): an omitted budget inherits the
            # project row, and a supplied timeout keeps its operational meaning only.
            budget = (
                body.resource_budget.model_dump(mode="json")
                if body.resource_budget is not None
                else dict(project["resource_budget"])
            )
            request = cast(
                ProofRequest,
                {
                    "schema_version": SchemaVersion.VALUE_1_0_0,
                    "id": f"proof:{uuid4().hex}",
                    "job_id": job_id,
                    "finding_id": finding_id,
                    "script_ref": body.script_ref,
                    "image_digest": body.image_digest,
                    "permission_mode": body.permission_mode,
                    "resource_budget": budget,
                    "timeout_seconds": int(cast(int, budget["timeout_seconds"])),
                },
            )
            validate_contract("ProofRequest", request)
            scheduler = ProofJobScheduler(
                tool=ToolIdentity(
                    name="proof-tool", version="1.0.0", image_digest=body.image_digest
                )
            )
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
                superseded = await repositories.findings.get_review(body.supersedes_review_id)
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

    @app.get("/api/findings/{finding_id}/reviews")
    async def finding_reviews(
        finding_id: str, _: Annotated[str, Depends(require_account)] = ""
    ) -> list[Review]:
        async with database.transaction() as repositories:
            await repositories.findings.get(finding_id)
            return await repositories.findings.list_reviews(finding_id)

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
                done, _ = await asyncio.wait({disconnected}, timeout=1.0)
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


_REPORT_DOWNLOADS = {
    "markdown": ("text/markdown; charset=utf-8", "vulnweaver-report.md"),
    "pdf": ("application/pdf", "vulnweaver-report.pdf"),
    "sarif": ("application/sarif+json", "vulnweaver-report.sarif"),
}


def _artifact_download_metadata(version: ArtifactVersion) -> tuple[str, str]:
    """Choose a safe media type and filename from immutable generation metadata."""
    generation_config = version["generation_config"]
    format_value = generation_config.get("format")
    if isinstance(format_value, str) and format_value in _REPORT_DOWNLOADS:
        return _REPORT_DOWNLOADS[format_value]

    filename = generation_config.get("filename")
    if isinstance(filename, str):
        safe_name = filename.replace("\\", "/").rsplit("/", 1)[-1]
        safe_name = "".join(
            character
            if ord(character) >= 32 and ord(character) != 127 and character not in {'"', ";"}
            else "_"
            for character in safe_name
        )[:128]
        if safe_name not in {"", ".", ".."}:
            return "application/octet-stream", safe_name
    return "application/octet-stream", "vulnweaver-artifact"


def _content_disposition(filename: str) -> str:
    """Emit an ASCII fallback plus an RFC 5987 UTF-8 filename."""
    ascii_fallback = filename.encode("ascii", "ignore").decode() or "download"
    encoded = quote(filename, safe="!#$&+-.^_`|~")
    return f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded}'


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
        key: value
        for key, value in values.items()
        if key not in {"review_model_api_key", "tier_api_keys", "provider_api_keys"}
    }
    parsed = ProductSettingsBody.model_validate({"schema_version": "1.0.0", **public_values})
    stored_tier_keys = values.get("tier_api_keys")
    stored_key_map: dict[str, object] = (
        {str(k): v for k, v in cast(dict[str, object], stored_tier_keys).items()}
        if isinstance(stored_tier_keys, dict)
        else {}
    )
    configured: dict[str, bool] = {
        tier: tier in stored_key_map for tier in _TIER_NAMES
    }
    stored_provider_keys = values.get("provider_api_keys")
    provider_key_map: dict[str, object] = (
        {str(k): v for k, v in cast(dict[str, object], stored_provider_keys).items()}
        if isinstance(stored_provider_keys, dict)
        else {}
    )
    providers_configured: dict[str, bool] = {
        provider.id: provider.id in provider_key_map for provider in parsed.model_providers
    }
    return ProductSettingsResponse(
        review_model_base_url=parsed.review_model_base_url,
        review_model_name=parsed.review_model_name,
        review_model_timeout_seconds=parsed.review_model_timeout_seconds,
        review_model_max_attempts=parsed.review_model_max_attempts,
        review_model_repair_attempts=parsed.review_model_repair_attempts,
        review_model_min_interval_seconds=parsed.review_model_min_interval_seconds,
        review_model_context_window_tokens=parsed.review_model_context_window_tokens,
        api_key_configured="review_model_api_key" in values,
        tool_image_digests=parsed.tool_image_digests,
        sandbox_budgets=parsed.sandbox_budgets,
        fuzz_budgets=parsed.fuzz_budgets,
        agent_loop_budgets=parsed.agent_loop_budgets,
        sandbox_runner_timeout_seconds=parsed.sandbox_runner_timeout_seconds,
        fuzz_runner_timeout_seconds=parsed.fuzz_runner_timeout_seconds,
        binary_command_timeout_seconds=parsed.binary_command_timeout_seconds,
        angr_enabled=parsed.angr_enabled,
        model_tiers=parsed.model_tiers,
        tier_api_keys_configured=configured,
        model_providers=parsed.model_providers,
        providers_api_key_configured=providers_configured,
        agent_model_bindings=parsed.agent_model_bindings,
    )


class ModelProbeError(Exception):
    """A safe probe failure message; never includes the API key or raw body."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _validate_model_providers(body: ProductSettingsBody) -> None:
    """Structural validation for the provider registry before it is stored."""

    seen_ids: set[str] = set()
    for provider in body.model_providers:
        if provider.id in seen_ids:
            raise ApiInputError(
                "duplicate_provider_id",
                f"provider id {provider.id!r} is defined twice",
                f"model_providers.{provider.id}.id",
            )
        seen_ids.add(provider.id)
        if provider.enabled:
            base_url = provider.base_url.strip().rstrip("/")
            if not base_url:
                raise ApiInputError(
                    "incomplete_model_configuration",
                    "an enabled provider requires a base URL",
                    f"model_providers.{provider.id}.base_url",
                )
            if not base_url.startswith(("https://", "http://")):
                raise ApiInputError(
                    "invalid_model_endpoint",
                    "model endpoint must use HTTP or HTTPS",
                    f"model_providers.{provider.id}.base_url",
                )
        seen_models: set[str] = set()
        for model in provider.models:
            if model.model_id in seen_models:
                raise ApiInputError(
                    "duplicate_model_id",
                    f"model {model.model_id!r} is listed twice in provider {provider.id!r}",
                    f"model_providers.{provider.id}.models.{model.model_id}",
                )
            seen_models.add(model.model_id)
            if model.thinking_mode == "custom" and model.thinking_budget_tokens < 1024:
                raise ApiInputError(
                    "invalid_thinking_budget",
                    "custom thinking mode requires a budget of at least 1024 tokens",
                    f"model_providers.{provider.id}.models.{model.model_id}"
                    ".thinking_budget_tokens",
                )
    bindings = body.agent_model_bindings
    for role in _TIER_NAMES:
        binding = getattr(bindings, role)
        if binding is None:
            continue
        provider = next((p for p in body.model_providers if p.id == binding.provider_id), None)
        if provider is None:
            raise ApiInputError(
                "unknown_binding_provider",
                f"{role} binding references provider {binding.provider_id!r} which is not defined",
                f"agent_model_bindings.{role}.provider_id",
            )
        if not any(m.model_id == binding.model_id for m in provider.models):
            raise ApiInputError(
                "unknown_binding_model",
                f"{role} binding references model {binding.model_id!r} which provider "
                f"{provider.id!r} does not list",
                f"agent_model_bindings.{role}.model_id",
            )


def _merge_provider_api_keys(
    body: ProductSettingsBody, previous: dict[str, object]
) -> dict[str, object]:
    """Merge stored provider keys with this request; prune keys of removed providers."""

    if body.clear_provider_api_keys and set(body.clear_provider_api_keys).intersection(
        body.provider_api_keys
    ):
        raise ApiInputError(
            "conflicting_secret_update",
            "API key cannot be replaced and cleared in the same request",
            "clear_provider_api_keys",
        )
    previous_keys = previous.get("provider_api_keys")
    previous_map: dict[str, object] = (
        {str(k): v for k, v in cast(dict[str, object], previous_keys).items()}
        if isinstance(previous_keys, dict)
        else {}
    )
    provider_ids = {provider.id for provider in body.model_providers}
    merged: dict[str, object] = {
        key: value
        for key, value in previous_map.items()
        if key in provider_ids and key not in body.clear_provider_api_keys
    }
    for provider_id, key_value in body.provider_api_keys.items():
        if provider_id in provider_ids and key_value:
            merged[provider_id] = key_value
    return merged


async def _probe_model_list(
    base_url: str, api_format: str, api_key: str | None
) -> list[str]:
    """Fetch a provider's model list; bounded, credential-free errors only."""

    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ModelProbeError("model endpoint must use HTTP or HTTPS")
    url = base_url if base_url.endswith("/models") else f"{base_url}/models"
    headers = {"Accept": "application/json"}
    if api_format == "anthropic-messages":
        headers["anthropic-version"] = "2023-06-01"
        if api_key:
            headers["x-api-key"] = api_key
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(url, headers=headers)
    except (httpx.TimeoutException, httpx.TransportError):
        raise ModelProbeError("could not reach the provider endpoint") from None
    if response.status_code != 200:
        raise ModelProbeError(f"provider answered with status {response.status_code}")
    try:
        payload: object = response.json()
    except ValueError:
        raise ModelProbeError("provider returned non-JSON content") from None
    if not isinstance(payload, dict):
        raise ModelProbeError("provider returned an unexpected model list shape")
    payload_object = cast(dict[str, object], payload)
    data = payload_object.get("data")
    if not isinstance(data, list):
        raise ModelProbeError("provider returned an unexpected model list shape")
    models: list[str] = []
    for item in cast(list[object], data)[:200]:
        if isinstance(item, dict):
            item_fields = cast(dict[str, object], item)
            item_id = item_fields.get("id")
            if isinstance(item_id, str) and item_id:
                models.append(item_id)
    return sorted(models)


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def _format_api_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
