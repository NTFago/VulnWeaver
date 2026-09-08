"""LangGraph task intake and initial-job orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypedDict, cast

from langgraph.graph import END, START, StateGraph  # pyright: ignore[reportMissingTypeStubs]
from vulnweaver_contracts import (
    ArtifactKind,
    FailureKind,
    Job,
    JobKind,
    JobRequestedEvent,
    JobStatus,
    JsonObject,
    PermissionMode,
    ResourceBudget,
    RetryPolicy,
    SchemaVersion,
    StructuredFailure,
    TaskStatus,
    TaskStatusChangedEvent,
    validate_contract,
)
from vulnweaver_domain import IllegalTransitionError, transition_task
from vulnweaver_model_gateway import ModelGateway
from vulnweaver_persistence import Database, EntityNotFound, PersistenceError
from vulnweaver_queue import RedisStreamsClient, StreamMessage
from vulnweaver_tool_runtime import (
    PolicyContext,
    PolicyDecisionStatus,
    PolicyEngine,
    ToolRegistry,
)

from vulnweaver_orchestrator.checkpoints import CheckpointStore


class FlowState(TypedDict):
    task_id: str
    artifact_version_ids: list[str]
    causation_id: str | None
    project_id: str
    object_refs: list[str]
    artifact_kinds: dict[str, str]
    resource_budget: ResourceBudget
    permission_mode: str
    job_kind: str
    tool_name: str
    tool_version: str
    tool_arguments: dict[str, object]
    policy_status: str
    policy_reason_codes: list[str]
    job_id: str
    checkpoint_node: str


def _empty_arguments() -> dict[str, object]:
    return {}


@dataclass(frozen=True, slots=True)
class InitialJobPolicy:
    """Static pipeline policy supplied by deployment configuration, not model output."""

    source_tool_name: str = "source-import"
    source_tool_version: str = "1.0.0"
    binary_tool_name: str = "binary-import"
    binary_tool_version: str = "1.0.0"
    source_job_kind: JobKind = JobKind.IMPORT
    binary_job_kind: JobKind = JobKind.IMPORT
    source_arguments: Mapping[str, object] = field(default_factory=_empty_arguments)
    binary_arguments: Mapping[str, object] = field(default_factory=_empty_arguments)
    retry_policy: RetryPolicy = field(
        default_factory=lambda: {
            "max_attempts": 2,
            "backoff_seconds": 1.0,
            "retryable_failure_kinds": [FailureKind.TIMEOUT, FailureKind.ENVIRONMENT],
        }
    )

    def __post_init__(self) -> None:
        validate_contract("RetryPolicy", self.retry_policy)


@dataclass(frozen=True, slots=True)
class OrchestratorSettings:
    consumer_name: str = "orchestrator-1"
    consumer_group: str = "orchestrators"
    read_block_milliseconds: int = 1000
    pending_idle_milliseconds: int = 30_000

    def __post_init__(self) -> None:
        if not self.consumer_name or not self.consumer_group:
            raise ValueError("orchestrator consumer and group names are required")
        if self.read_block_milliseconds < 1 or self.read_block_milliseconds > 60_000:
            raise ValueError("orchestrator read block must be between 1 and 60000 ms")
        if self.pending_idle_milliseconds < 1:
            raise ValueError("orchestrator pending idle duration must be positive")


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    task_id: str | None
    job_id: str | None
    handled: bool
    acknowledged: bool
    status: str
    failure: StructuredFailure | None = None


class OrchestrationError(RuntimeError):
    def __init__(self, failure: StructuredFailure) -> None:
        self.failure = failure
        super().__init__(failure["message"])


class Orchestrator:
    """Consume task requests and create the first policy-approved Job atomically."""

    def __init__(
        self,
        database: Database,
        queue: RedisStreamsClient,
        registry: ToolRegistry,
        *,
        policy_engine: PolicyEngine | None = None,
        checkpoint_store: CheckpointStore | None = None,
        model_gateway: ModelGateway | None = None,
        initial_job_policy: InitialJobPolicy | None = None,
        settings: OrchestratorSettings | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = database
        self._queue = queue
        self._registry = registry
        self._policy = policy_engine or PolicyEngine(registry)
        self._checkpoints = checkpoint_store
        self._model_gateway = model_gateway
        self._initial_policy = initial_job_policy or InitialJobPolicy()
        self._settings = settings or OrchestratorSettings()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._stale_cursor = "0-0"
        self._prefer_fresh = False
        self._graph: Any = self._build_graph()

    async def process_once(self) -> tuple[OrchestrationResult, ...]:
        """Process one bounded event batch; permanent poison events are ACKed."""

        stream = self._queue.streams.events
        await self._queue.ensure_group(stream, self._settings.consumer_group)
        messages: list[StreamMessage] = []
        capacity = 100
        if self._prefer_fresh:
            messages.extend(
                await self._queue.read_group(
                    stream,
                    self._settings.consumer_group,
                    self._settings.consumer_name,
                    count=capacity,
                    block_milliseconds=None,
                )
            )
        if len(messages) < capacity:
            claimed = await self._queue.claim_stale(
                stream,
                self._settings.consumer_group,
                self._settings.consumer_name,
                min_idle_milliseconds=self._settings.pending_idle_milliseconds,
                count=capacity - len(messages),
                start_id=self._stale_cursor,
            )
            self._stale_cursor = claimed.next_start_id
            messages.extend(claimed.messages)
        if not self._prefer_fresh and len(messages) < capacity:
            messages.extend(
                await self._queue.read_group(
                    stream,
                    self._settings.consumer_group,
                    self._settings.consumer_name,
                    count=capacity - len(messages),
                    block_milliseconds=None,
                )
            )
        if not messages:
            messages = await self._queue.read_group(
                stream,
                self._settings.consumer_group,
                self._settings.consumer_name,
                count=capacity,
                block_milliseconds=self._settings.read_block_milliseconds,
            )
        self._prefer_fresh = not self._prefer_fresh
        results: list[OrchestrationResult] = []
        for message in messages:
            result = await self.handle_message(message)
            if result.acknowledged:
                await self._queue.acknowledge(
                    stream, self._settings.consumer_group, message.message_id
                )
            results.append(result)
        return tuple(results)

    async def handle_message(self, message: StreamMessage) -> OrchestrationResult:
        event = message.event
        if event["event_type"] != "task.requested":
            return OrchestrationResult(None, None, True, True, "ignored")
        task_event = event
        task_id = task_event["payload"]["task_id"]
        try:
            validate_contract("TaskRequestedEvent", task_event)
            checkpoint = await self._latest_checkpoint(task_id)
            if checkpoint is not None and checkpoint.node == "initial_job_persisted":
                job_id = cast(str, checkpoint.state["job_id"])
                return OrchestrationResult(task_id, job_id, True, True, "already_scheduled")
            initial_state = cast(
                FlowState,
                {
                    "task_id": task_id,
                    "artifact_version_ids": task_event["payload"]["artifact_version_ids"],
                    "causation_id": task_event["event_id"],
                },
            )
            if checkpoint is not None:
                initial_state.update(cast(FlowState, checkpoint.state))
            state = cast(FlowState, await self._graph.ainvoke(initial_state))
            return OrchestrationResult(
                task_id,
                state.get("job_id"),
                True,
                True,
                state.get("policy_status", "scheduled"),
            )
        except OrchestrationError as error:
            await self._fail_task(task_id, error.failure, task_event["event_id"])
            return OrchestrationResult(task_id, None, True, True, "failed", error.failure)
        except (EntityNotFound, PersistenceError, ValueError) as error:
            failure = _failure(
                "orchestration_input_rejected",
                "task request could not be orchestrated",
                "validation",
                retryable=False,
                details={"error_type": type(error).__name__},
            )
            await self._fail_task(task_id, failure, task_event["event_id"])
            return OrchestrationResult(task_id, None, True, True, "failed", failure)
        except Exception as error:
            # Unknown database/queue/framework failures remain pending for at-least-once recovery.
            failure = _failure(
                "orchestration_retryable_failure",
                "orchestration encountered a transient internal failure",
                FailureKind.INTERNAL,
                retryable=True,
                details={"error_type": type(error).__name__},
            )
            return OrchestrationResult(
                task_id, None, False, False, "retryable_failure", failure
            )

    async def _latest_checkpoint(self, task_id: str):
        if self._checkpoints is None:
            return None
        return await self._checkpoints.latest(task_id)

    def _build_graph(self) -> Any:
        graph: Any = StateGraph(FlowState)
        graph.add_node("validate_inputs", self._validate_inputs)
        graph.add_node("select_pipeline", self._select_pipeline)
        graph.add_node("authorize_initial_job", self._authorize_initial_job)
        graph.add_node("persist_initial_job", self._persist_initial_job)
        graph.add_conditional_edges(
            START,
            self._resume_route,
            {
                "validate_inputs": "validate_inputs",
                "select_pipeline": "select_pipeline",
                "authorize_initial_job": "authorize_initial_job",
                "persist_initial_job": "persist_initial_job",
                "complete": END,
            },
        )
        graph.add_edge("validate_inputs", "select_pipeline")
        graph.add_edge("select_pipeline", "authorize_initial_job")
        graph.add_edge("authorize_initial_job", "persist_initial_job")
        graph.add_edge("persist_initial_job", END)
        return graph.compile()

    @staticmethod
    def _resume_route(state: FlowState) -> str:
        checkpoint = state.get("checkpoint_node")
        return {
            None: "validate_inputs",
            "validate_inputs": "select_pipeline",
            "select_pipeline": "authorize_initial_job",
            "authorize_initial_job": "persist_initial_job",
            "initial_job_persisted": "complete",
        }.get(checkpoint, "validate_inputs")

    async def _validate_inputs(self, state: FlowState) -> FlowState:
        task_id = state["task_id"]
        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            project = await repositories.projects.get(task["project_id"])
            expected = task["artifact_version_ids"]
            actual = state["artifact_version_ids"]
            if expected != actual:
                raise OrchestrationError(
                    _failure(
                        "task_artifact_reference_mismatch",
                        "task.requested artifact references do not match the persisted Task",
                        "validation",
                        details={"task_id": task_id},
                    )
                )
            object_refs: list[str] = []
            artifact_kinds: dict[str, str] = {}
            for version_id in actual:
                version = await repositories.artifacts.get_version(version_id)
                artifact = await repositories.artifacts.get(version["artifact_id"])
                if artifact["project_id"] != task["project_id"]:
                    raise OrchestrationError(
                        _failure(
                            "artifact_project_mismatch",
                            "artifact version is outside the task project",
                            "validation",
                            details={"artifact_version_id": version_id},
                        )
                    )
                object_refs.append(version["object_ref"])
                artifact_kinds[version["object_ref"]] = str(artifact["kind"])
            next_state = {
                **state,
                "project_id": task["project_id"],
                "object_refs": object_refs,
                "artifact_kinds": artifact_kinds,
                "resource_budget": project["resource_budget"],
                "permission_mode": str(project["permission_mode"]),
                "checkpoint_node": "validate_inputs",
            }
        await self._save_checkpoint(task_id, "validate_inputs", next_state)
        return cast(FlowState, next_state)

    async def _select_pipeline(self, state: FlowState) -> FlowState:
        kinds = {ArtifactKind(kind) for kind in state["artifact_kinds"].values()}
        source_kinds = {ArtifactKind.SOURCE_ARCHIVE, ArtifactKind.SOURCE_REPOSITORY}
        binary_kinds = {ArtifactKind.ELF, ArtifactKind.PE}
        if kinds and kinds <= source_kinds:
            selected = (
                self._initial_policy.source_job_kind,
                self._initial_policy.source_tool_name,
                self._initial_policy.source_tool_version,
                dict(self._initial_policy.source_arguments),
            )
        elif kinds and kinds <= binary_kinds:
            selected = (
                self._initial_policy.binary_job_kind,
                self._initial_policy.binary_tool_name,
                self._initial_policy.binary_tool_version,
                dict(self._initial_policy.binary_arguments),
            )
        else:
            raise OrchestrationError(
                _failure(
                    "unsupported_artifact_pipeline",
                    "task contains mixed or unsupported artifact kinds",
                    "validation",
                    details={"artifact_kinds": sorted(kinds)},
                )
            )
        next_state = {
            **state,
            "job_kind": str(selected[0]),
            "tool_name": selected[1],
            "tool_version": selected[2],
            "tool_arguments": selected[3],
            "checkpoint_node": "select_pipeline",
        }
        await self._save_checkpoint(state["task_id"], "select_pipeline", next_state)
        return cast(FlowState, next_state)

    async def _authorize_initial_job(self, state: FlowState) -> FlowState:
        plan = {
            "schema_version": SchemaVersion.VALUE_1_0_0,
            "id": _stable_identifier("plan", state["task_id"], "initial"),
            "task_id": state["task_id"],
            "agent_run_id": _stable_identifier("run", state["task_id"], "initial"),
            "steps": [
                {
                    "step_id": _stable_identifier("step", state["task_id"], "initial"),
                    "tool_name": state["tool_name"],
                    "tool_version": state["tool_version"],
                    "input_refs": state["object_refs"],
                    "arguments": state["tool_arguments"],
                    "expected_output_types": ["artifact", "analysis_result"],
                    "reason": "select the first registered pipeline step for the task input",
                }
            ],
            "created_at": _timestamp(self._clock()),
        }
        decision = self._policy.evaluate(
            plan,
            PolicyContext(
                artifact_kinds=state["artifact_kinds"],
                resource_budget=state["resource_budget"],
                permission_mode=PermissionMode(state["permission_mode"]),
            ),
        )
        if decision.status is PolicyDecisionStatus.DENIED:
            raise OrchestrationError(
                _failure(
                    "initial_job_policy_denied",
                    "Policy Engine denied the initial analysis step",
                    "policy",
                    details={"reason_codes": list(decision.reason_codes)},
                )
            )
        next_state = {
            **state,
            "policy_status": decision.status.value,
            "policy_reason_codes": list(decision.reason_codes),
            "checkpoint_node": "authorize_initial_job",
        }
        await self._save_checkpoint(state["task_id"], "authorize_initial_job", next_state)
        return cast(FlowState, next_state)

    async def _persist_initial_job(self, state: FlowState) -> FlowState:
        task_id = state["task_id"]
        job_id = _stable_identifier("job", task_id, "initial")
        now = _timestamp(self._clock())
        status = (
            JobStatus.WAITING_PERMISSION
            if state["policy_status"] == PolicyDecisionStatus.WAITING_PERMISSION.value
            else JobStatus.QUEUED
        )
        job = Job(
            schema_version=SchemaVersion.VALUE_1_0_0,
            id=job_id,
            task_id=task_id,
            kind=JobKind(state["job_kind"]),
            input_refs=state["object_refs"],
            status=status,
            idempotency_key=_stable_identifier("initial", task_id),
            resource_budget=state["resource_budget"],
            retry_policy=self._initial_policy.retry_policy,
            attempt=0,
            lease=None,
            failure=None,
            created_at=now,
            updated_at=now,
        )
        async with self._database.transaction() as repositories:
            task = await repositories.tasks.get(task_id)
            if task["status"] is TaskStatus.CREATED:
                _ensure_task_transition(task["status"], TaskStatus.VALIDATING)
                updated = await repositories.tasks.set_status(task_id, TaskStatus.VALIDATING)
                sequence = await repositories.task_events.next_sequence(task_id)
                await repositories.task_events.append(
                    _task_status_event(
                        task_id,
                        updated.previous_status,
                        TaskStatus.VALIDATING,
                        sequence,
                        now,
                        state.get("causation_id"),
                    )
                )
            elif task["status"] not in {TaskStatus.VALIDATING, TaskStatus.ANALYZING}:
                raise OrchestrationError(
                    _failure(
                        "task_not_schedulable",
                        "task is not in a schedulable orchestration state",
                        "validation",
                        details={"status": str(task["status"])},
                    )
                )
            if status is JobStatus.WAITING_PERMISSION:
                await repositories.jobs.create_without_outbox(job)
            else:
                event = _job_requested_event(job, task_id, state.get("causation_id"), now)
                await repositories.jobs.enqueue_with_outbox(job, event)
        next_state = {**state, "job_id": job_id, "checkpoint_node": "initial_job_persisted"}
        await self._save_checkpoint(task_id, "initial_job_persisted", next_state)
        return cast(FlowState, next_state)

    async def _save_checkpoint(self, task_id: str, node: str, state: Mapping[str, object]) -> None:
        if self._checkpoints is not None:
            await self._checkpoints.save(
                task_id,
                node,
                state,
                created_at=_timestamp(self._clock()),
            )

    async def _fail_task(
        self, task_id: str, failure: StructuredFailure, causation_id: str
    ) -> None:
        async with self._database.transaction() as repositories:
            try:
                task = await repositories.tasks.get(task_id)
            except EntityNotFound:
                return
            if task["status"] in {TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.FAILED}:
                return
            previous = task["status"]
            _ensure_task_transition(previous, TaskStatus.FAILED)
            updated = await repositories.tasks.set_status(task_id, TaskStatus.FAILED)
            sequence = await repositories.task_events.next_sequence(task_id)
            await repositories.task_events.append(
                _task_status_event(
                    task_id,
                    updated.previous_status,
                    TaskStatus.FAILED,
                    sequence,
                    _timestamp(self._clock()),
                    causation_id,
                )
            )


def _ensure_task_transition(current: TaskStatus, target: TaskStatus) -> None:
    try:
        transition_task(current, target)
    except IllegalTransitionError as error:
        raise OrchestrationError(
            _failure(
                "illegal_task_transition",
                str(error),
                "validation",
                details={"current": str(current), "target": str(target)},
            )
        ) from error


def _job_requested_event(
    job: Job, task_id: str, causation_id: str | None, occurred_at: str
) -> JobRequestedEvent:
    return JobRequestedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_stable_identifier("event", job["id"], "requested"),
        event_type="job.requested",
        aggregate_id=job["id"],
        sequence=job["attempt"],
        occurred_at=occurred_at,
        correlation_id=task_id,
        causation_id=causation_id,
        payload={
            "job_id": job["id"],
            "task_id": task_id,
            "job_kind": job["kind"],
            "attempt": job["attempt"],
        },
    )


def _task_status_event(
    task_id: str,
    previous: TaskStatus,
    status: TaskStatus,
    sequence: int,
    occurred_at: str,
    causation_id: str | None,
) -> TaskStatusChangedEvent:
    return TaskStatusChangedEvent(
        schema_version=SchemaVersion.VALUE_1_0_0,
        event_id=_stable_identifier("event", task_id, status.value, str(sequence)),
        event_type="task.status_changed",
        aggregate_id=task_id,
        sequence=sequence,
        occurred_at=occurred_at,
        correlation_id=task_id,
        causation_id=causation_id,
        payload={
            "task_id": task_id,
            "previous_status": previous,
            "status": status,
            "result": None,
        },
    )


def _failure(
    code: str,
    message: str,
    kind: FailureKind | str,
    *,
    retryable: bool = False,
    details: Mapping[str, object] | None = None,
) -> StructuredFailure:
    return StructuredFailure(
        code=code,
        kind=FailureKind(kind),
        message=message,
        retryable=retryable,
        details=cast(JsonObject, dict(details or {})),
    )


def _stable_identifier(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}:{digest}"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("orchestrator timestamps require timezone-aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
