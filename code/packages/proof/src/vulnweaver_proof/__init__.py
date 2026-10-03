"""Policy-gated proof and exploit execution orchestration."""

from vulnweaver_proof.auto_exploit import (
    POC_VERIFICATION_BASELINE,
    AutoExploitError,
    AutoExploitScheduler,
    ExploitScriptGenerator,
    GeneratedExploit,
)
from vulnweaver_proof.auto_poc import POC_VERIFICATION, PocVerificationScheduler
from vulnweaver_proof.bundle import (
    ExecutionBundleError,
    build_execution_bundle,
    load_execution_bundle_manifest,
    load_execution_bundle_member,
)
from vulnweaver_proof.client import SandboxRunnerClient
from vulnweaver_proof.executor import (
    ProofExecutionError,
    ProofExecutionService,
    ProofJobExecutor,
    ProofRun,
)
from vulnweaver_proof.profiles import proof_command_profile, proof_tool_spec
from vulnweaver_proof.protection_analysis import ProtectionScan, scan_target_protections
from vulnweaver_proof.scheduler import ProofJobScheduler
from vulnweaver_proof.validation import (
    GeneratedScriptPolicyResult,
    ScriptRefOwnershipError,
    ensure_script_ref_belongs_to_project,
    validate_generated_script,
)
from vulnweaver_proof.verifier import (
    REPORT_FILE_NAME,
    ObservationError,
    behavior_is_verified,
    differential_evidence_from_observation,
    evidence_from_observation,
    observation_is_consistent,
    observation_is_reproducible,
    parse_observation,
    poc_result_from_observation,
)

__all__ = [
    "AutoExploitError",
    "AutoExploitScheduler",
    "ExecutionBundleError",
    "ExploitScriptGenerator",
    "GeneratedExploit",
    "ObservationError",
    "POC_VERIFICATION",
    "POC_VERIFICATION_BASELINE",
    "PocVerificationScheduler",
    "ProofExecutionError",
    "ProofExecutionService",
    "ProofJobExecutor",
    "ProofJobScheduler",
    "ProofRun",
    "ProtectionScan",
    "REPORT_FILE_NAME",
    "SandboxRunnerClient",
    "ScriptRefOwnershipError",
    "behavior_is_verified",
    "build_execution_bundle",
    "differential_evidence_from_observation",
    "load_execution_bundle_manifest",
    "load_execution_bundle_member",
    "evidence_from_observation",
    "observation_is_consistent",
    "observation_is_reproducible",
    "ensure_script_ref_belongs_to_project",
    "GeneratedScriptPolicyResult",
    "parse_observation",
    "poc_result_from_observation",
    "scan_target_protections",
    "validate_generated_script",
    "proof_command_profile",
    "proof_tool_spec",
]
