from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "current/context_bridge/PROJECT_INSTRUCTIONS_CURRENT.md"
ACCEPTANCE = ROOT / "current/context_bridge/CONTINUITY_ACCEPTANCE_CURRENT.md"
KERNEL = ROOT / "tools/execution_hardening_kernel.py"
HARNESS = ROOT / "tools/execution_hardening_acceptance.py"
MATERIAL_ACCEPTANCE = ROOT / "tools/material_predicate_acceptance.py"
MATERIAL_ADJUDICATOR = ROOT / "tools/material_predicate_acceptance_adjudicator.py"
API_VISIBILITY = ROOT / "tools/github_actions_visibility_self_test.py"
WORKFLOW = ROOT / ".github/workflows/execution-hardening-acceptance.yml"
A1_RECEIPT = ROOT / "audits/EXECUTION_HARDENING_A1_PUBLIC_CURRENT.json"
B0_RECEIPT = ROOT / "audits/EXECUTION_HARDENING_B0_INFRA_CURRENT.json"

EXPECTED_A1_SOURCE_BLOBS = {
    "tools/execution_hardening_kernel.py": "09d55539343c442bc9db27a640e3d7ecfe24f1a1",
    "tools/material_predicate_acceptance.py": "cfb88c6a18801edb07e2c45be935dca66387b814",
    "tools/github_actions_visibility_self_test.py": "0c77de2690d3484bc36987425dfcfdc6e09fcd76",
}


def require(text: str, marker: str, where: str) -> None:
    if marker not in text:
        raise AssertionError(f"missing {marker!r} in {where}")


def forbid(text: str, marker: str, where: str) -> None:
    if marker in text:
        raise AssertionError(f"forbidden {marker!r} in {where}")


def validate_private_pointer(workflow: str) -> None:
    for marker in [
        "workflow_dispatch:",
        "public-validator-pointer:",
        "if: ${{ false }}",
        "runs-on: ubuntu-latest",
        "chch13/execution-hardening-validator",
        "audits/EXECUTION_HARDENING_A1_PUBLIC_CURRENT.json",
        "Do not substitute self-hosted execution for A1",
    ]:
        require(workflow, marker, "private hardening workflow pointer")
    for marker in [
        "push:",
        "uses:",
        "actions/checkout",
        "python ",
        "powershell",
        "pwsh",
        "curl ",
        "gh ",
    ]:
        forbid(workflow, marker, "private hardening workflow pointer")


def validate_a1_receipt(receipt: Mapping[str, object], local_blobs: Mapping[str, str] | None = None) -> None:
    if receipt.get("state") != "PASS":
        raise AssertionError("A1 receipt is not PASS")
    if receipt.get("acceptance") != "A1_MATERIAL_PREDICATE":
        raise AssertionError("A1 acceptance identity mismatch")
    if receipt.get("route_mode") != "PUBLIC_GITHUB_HOSTED_VALIDATOR":
        raise AssertionError("A1 route is not public hosted validator")
    if receipt.get("self_hosted_substitution_for_a1") is not False:
        raise AssertionError("self-hosted substitution for A1 is not explicitly false")
    if receipt.get("unknown_result_count") != 0:
        raise AssertionError("A1 unknown result count is nonzero")
    fixture = receipt.get("fixture_trials")
    meta = receipt.get("metamorphic_trials")
    if not isinstance(fixture, Mapping) or not isinstance(meta, Mapping):
        raise AssertionError("A1 trial receipts missing")
    if (fixture.get("executed"), fixture.get("passed"), fixture.get("failed")) != (65, 65, 0):
        raise AssertionError("A1 fixture counts are not 65/65/0")
    if (meta.get("executed"), meta.get("passed"), meta.get("failed")) != (30, 30, 0):
        raise AssertionError("A1 metamorphic counts are not 30/30/0")
    source_blobs = receipt.get("source_blob_shas")
    if not isinstance(source_blobs, Mapping):
        raise AssertionError("A1 source blob map missing")
    if dict(source_blobs) != EXPECTED_A1_SOURCE_BLOBS:
        raise AssertionError("A1 receipt source blob identity drift")
    if local_blobs is not None and dict(local_blobs) != EXPECTED_A1_SOURCE_BLOBS:
        raise AssertionError("local A1 source blobs no longer match accepted A1 blobs")


def validate_b0_receipt(receipt: Mapping[str, object]) -> None:
    if receipt.get("state") != "PASS":
        raise AssertionError("B0 infrastructure receipt is not PASS")
    if receipt.get("claim") != "B0_INFRASTRUCTURE_BEHAVIOR_ONLY":
        raise AssertionError("B0 receipt claim boundary drift")
    if receipt.get("b0_exact_content_contract_status") != "UNKNOWN_NOT_RECOVERED_FROM_CURRENT_REPOSITORY":
        raise AssertionError("B0 content-contract UNKNOWN boundary was silently changed")
    if receipt.get("b0_canonical_content_inventory_status") != "NOT_YET_BUILT":
        raise AssertionError("B0 canonical content inventory was prematurely promoted")
    if receipt.get("whole_execution_hardening_complete") is not False:
        raise AssertionError("whole execution hardening was prematurely completed")


def validate_static_bindings(*, project: str, acceptance: str, kernel: str, harness: str, material_acceptance: str, material_adjudicator: str, api_visibility: str) -> None:
    for marker in ["INTENT_RECEIPT", "CORRECTION INVALIDATION", "IDENTITY READBACK", "EFFECT READBACK", "INDEPENDENT_EVIDENCE_LINEAGE_COUNT", "ROUTE_AUTHORITY != ROUTE_AVAILABILITY", "OPERATION_RESOURCE_FOOTPRINT", "PARTIALLY_APPLIED", "TARGET_COMMITTED", "FINAL_THEME_CLOSURE", "FAILURE_FAMILY_ID", "WHY UNKNOWN", "Cross-guard precedence"]:
        require(project, marker, str(PROJECT))
    for idx in range(1, 16):
        require(acceptance, f"EH{idx:02d}", str(ACCEPTANCE))
    for marker in ["EXECUTION_HARDENING_TRIALS=75", "EXECUTION_HARDENING_VARIANTS_PER_CASE=5", "EXECUTION_HARDENING_VARIANT_MODE=MATERIAL_INPUT_VARIATION", "EXECUTION_HARDENING_CRITICAL_ERRORS=0", "HOST_FRESH_CONTEXT_PROVEN=NO"]:
        require(acceptance, marker, str(ACCEPTANCE))
    for marker in ["class IntentReceipt", "def evaluate_readback", "class MutationPhase", "def recover_lost_reply", "class ResourceFootprint", "def footprints_conflict", "def failure_family_id", "def resolve_route", "def final_theme_closure", "def unknown_recovery_packet", "CROSS_GUARD_PRECEDENCE", "class MaterialClassification", "class ExecutionNode", "def classify_material_graph", "def execution_graph_digest", "MATERIAL_PRIMITIVES", "READ_ONLY_PRIMITIVES"]:
        require(kernel, marker, str(KERNEL))
    require(harness, "from execution_hardening_kernel import", str(HARNESS))
    for forbidden in ["class IntentReceipt", "class MutationPhase", "class ResourceFootprint", "def evaluate_readback", "def recover_lost_reply", "def resolve_route", "def final_theme_closure"]:
        forbid(harness, forbidden, str(HARNESS))
    require(harness, "TOTAL_EXPECTED = CASES * VARIANTS", str(HARNESS))
    require(harness, "HOST_FRESH_CONTEXT_PROVEN=NO", str(HARNESS))
    for marker in ["from execution_hardening_kernel import", "FIXTURE_CASES = 13", "METAMORPHIC_CASES = 6", "EXPECTED_FIXTURE_COUNT = FIXTURE_CASES * VARIANTS", "EXPECTED_METAMORPHIC_COUNT = METAMORPHIC_CASES * VARIANTS"]:
        require(material_acceptance, marker, str(MATERIAL_ACCEPTANCE))
    for marker in ["EXPECTED_FIXTURE_COUNT = 65", "EXPECTED_METAMORPHIC_COUNT = 30", "material-predicate-acceptance-receipt/v1", "API_VISIBILITY_NOT_PASS", "API_VISIBILITY_COMMIT_MISMATCH"]:
        require(material_adjudicator, marker, str(MATERIAL_ADJUDICATOR))
    for marker in ["PLATFORM_TRUST_ASSUMPTION_GITHUB_CONTROL_PLANE", "PAGINATION_INCOMPLETE", "RUNWIDE_ATTEMPT_UNIVERSE_MISMATCH", "CANARY_COUNT", "NETWORK_RETRIES_EXHAUSTED", "TRANSIENT_HTTP_"]:
        require(api_visibility, marker, str(API_VISIBILITY))
    combined = project + acceptance + kernel + harness + material_acceptance + material_adjudicator + api_visibility
    if "HOST_FRESH_CONTEXT_PROVEN=YES" in combined:
        raise AssertionError("opaque fresh-context host behavior was falsely promoted to YES")


def git_blob(path: str) -> str:
    return subprocess.check_output(["git", "hash-object", path], cwd=ROOT, text=True).strip()


def main() -> None:
    project = PROJECT.read_text(encoding="utf-8")
    acceptance = ACCEPTANCE.read_text(encoding="utf-8")
    kernel = KERNEL.read_text(encoding="utf-8")
    harness = HARNESS.read_text(encoding="utf-8")
    material_acceptance = MATERIAL_ACCEPTANCE.read_text(encoding="utf-8")
    material_adjudicator = MATERIAL_ADJUDICATOR.read_text(encoding="utf-8")
    api_visibility = API_VISIBILITY.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    a1_receipt = json.loads(A1_RECEIPT.read_text(encoding="utf-8"))
    b0_receipt = json.loads(B0_RECEIPT.read_text(encoding="utf-8"))
    validate_static_bindings(project=project, acceptance=acceptance, kernel=kernel, harness=harness, material_acceptance=material_acceptance, material_adjudicator=material_adjudicator, api_visibility=api_visibility)
    validate_private_pointer(workflow)
    local_blobs = {path: git_blob(path) for path in EXPECTED_A1_SOURCE_BLOBS}
    validate_a1_receipt(a1_receipt, local_blobs)
    validate_b0_receipt(b0_receipt)
    print("EXECUTION_HARDENING_STRUCTURAL_ACCEPTANCE_PASS")
    print("EXECUTION_HARDENING_STRUCTURAL_CRITICAL_ERRORS=0")
    print("STRUCTURAL_ROUTE_MODE=PUBLIC_VALIDATOR_POINTER")
    print("PRIVATE_HOSTED_JOB_ALLOCATION=DISABLED_BY_STRUCTURE")
    print("A1_PUBLIC_RECEIPT_BOUND=YES")
    print("B0_CONTENT_INVENTORY_COMPLETE=NO")
    print("HOST_FRESH_CONTEXT_PROVEN=NO")


if __name__ == "__main__":
    main()
