from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from typing import FrozenSet, Iterable, Mapping, Sequence


CROSS_GUARD_PRECEDENCE = (
    "SAFETY_PARTIAL_MUTATION_STABILIZATION",
    "LATEST_USER_AUTHORITY",
    "INTENT_TARGET_RELOCK",
    "ROUTE_RESOURCE_LOCK",
    "ACTION",
    "IDENTITY_EFFECT_READBACK",
    "FINAL_THEME_CLOSURE",
)


@dataclass(frozen=True)
class IntentReceipt:
    user_request_anchor: str
    target: str
    objective: str
    done_when: str
    selector_evidence: str
    status: str = "ACTIVE"
    invalidation_reason: str | None = None


def make_intent_receipt(
    *,
    user_request_anchor: str,
    target: str,
    objective: str,
    done_when: str,
    selector_evidence: str,
) -> IntentReceipt:
    fields = [user_request_anchor, target, objective, done_when, selector_evidence]
    if any(not str(value).strip() for value in fields):
        raise ValueError("intent receipt requires non-empty anchor/target/objective/done_when/selector evidence")
    return IntentReceipt(
        user_request_anchor=user_request_anchor.strip(),
        target=target.strip(),
        objective=objective.strip(),
        done_when=done_when.strip(),
        selector_evidence=selector_evidence.strip(),
    )


def invalidate_intent(receipt: IntentReceipt, *, reason: str) -> IntentReceipt:
    if receipt.status != "ACTIVE":
        return receipt
    if not reason.strip():
        raise ValueError("invalidation reason required")
    return replace(receipt, status="INVALIDATED", invalidation_reason=reason.strip())


@dataclass(frozen=True)
class ReadbackResult:
    identity_ok: bool
    effect_ok: bool | None
    independent_ok: bool | None
    accepted: bool
    reason: str


def evaluate_readback(
    *,
    expected_identity: str,
    observed_identity: str,
    material_effect_required: bool,
    expected_effect: str | None = None,
    observed_effect: str | None = None,
    independent_evidence_required: bool = False,
    independent_lineage_count: int = 0,
) -> ReadbackResult:
    identity_ok = bool(expected_identity) and expected_identity == observed_identity
    if not identity_ok:
        return ReadbackResult(False, None, None, False, "TARGET_IDENTITY_MISMATCH")

    effect_ok: bool | None = None
    if material_effect_required:
        effect_ok = bool(expected_effect) and expected_effect == observed_effect
        if not effect_ok:
            return ReadbackResult(True, False, None, False, "DESIRED_EFFECT_MISMATCH")

    independent_ok: bool | None = None
    if independent_evidence_required:
        independent_ok = independent_lineage_count >= 1
        if not independent_ok:
            return ReadbackResult(True, effect_ok, False, False, "INDEPENDENT_EVIDENCE_MISSING")

    return ReadbackResult(True, effect_ok, independent_ok, True, "READBACK_ACCEPTED")


class MutationPhase(IntEnum):
    PREPARED = 10
    REQUEST_COMMITTED = 20
    PARTIALLY_APPLIED = 30
    TARGET_COMMITTED = 40
    POSTCONDITION_VERIFIED = 50
    ACCEPTED = 60


class TargetMutationState(str, Enum):
    UNAPPLIED = "UNAPPLIED"
    PARTIAL = "PARTIAL"
    COMMITTED = "COMMITTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LostReplyDecision:
    action: str
    replay_allowed: bool
    reason: str


def recover_lost_reply(
    phase: MutationPhase | None,
    target_state: TargetMutationState,
) -> LostReplyDecision:
    if phase is None or target_state is TargetMutationState.UNKNOWN:
        return LostReplyDecision("FAIL_CLOSED_READ_PHASE_AND_TARGET_STATE", False, "MUTATION_STATE_UNKNOWN")

    if target_state is TargetMutationState.PARTIAL:
        return LostReplyDecision("RESUME_OR_ROLLBACK_TO_STABLE_STATE", False, "PARTIAL_MUTATION_MUST_NOT_BLIND_REPLAY")

    if target_state is TargetMutationState.COMMITTED:
        return LostReplyDecision("DO_NOT_REPLAY_CONTINUE_VERIFICATION", False, "TARGET_COMMIT_ALREADY_REACHED")

    if phase >= MutationPhase.PARTIALLY_APPLIED:
        return LostReplyDecision("FAIL_CLOSED_RECONCILE_PHASE_TARGET_STATE", False, "PHASE_TARGET_STATE_CONFLICT")

    return LostReplyDecision("RETRY_SAME_INTENT_WITH_SAME_OPERATION_ID", True, "UNAPPLIED_CONFIRMED_BY_PHASE_AND_TARGET")


@dataclass(frozen=True)
class ResourceFootprint:
    read_set: FrozenSet[str] = frozenset()
    write_set: FrozenSet[str] = frozenset()
    exclusive_set: FrozenSet[str] = frozenset()
    process_set: FrozenSet[str] = frozenset()
    persistence_set: FrozenSet[str] = frozenset()
    gui_set: FrozenSet[str] = frozenset()
    gpu_set: FrozenSet[str] = frozenset()

    @staticmethod
    def from_mapping(values: Mapping[str, Iterable[str]]) -> "ResourceFootprint":
        def fs(name: str) -> FrozenSet[str]:
            return frozenset(str(x) for x in values.get(name, ()) if str(x))

        return ResourceFootprint(
            read_set=fs("READ_SET"),
            write_set=fs("WRITE_SET"),
            exclusive_set=fs("EXCLUSIVE_SET"),
            process_set=fs("PROCESS_SET"),
            persistence_set=fs("PERSISTENCE_SET"),
            gui_set=fs("GUI_SET"),
            gpu_set=fs("GPU_SET"),
        )


def footprints_conflict(a: ResourceFootprint, b: ResourceFootprint) -> bool:
    a_writeish = a.write_set | a.exclusive_set | a.process_set | a.persistence_set | a.gui_set | a.gpu_set
    b_writeish = b.write_set | b.exclusive_set | b.process_set | b.persistence_set | b.gui_set | b.gpu_set
    if a_writeish & (b.read_set | b_writeish):
        return True
    if b_writeish & (a.read_set | a_writeish):
        return True
    return False


def failure_family_id(*, subsystem: str, execution_phase: str, violated_invariant: str) -> str:
    normalized = [subsystem.strip().upper(), execution_phase.strip().upper(), violated_invariant.strip().upper()]
    if any(not value for value in normalized):
        raise ValueError("failure family requires subsystem/phase/invariant")
    return "::".join(normalized)


def failure_family_action(family_occurrences: int, *, threshold: int = 2) -> str:
    if family_occurrences < 1 or threshold < 2:
        raise ValueError("invalid failure-family count/threshold")
    return "REAUDIT_ASSUMPTION_IDENTITY_METHOD" if family_occurrences >= threshold else "BOUNDED_REPAIR_ALLOWED"


@dataclass(frozen=True)
class RouteDecision:
    authority_state: str
    availability_state: str
    selected_route: str | None
    discovery_allowed: bool
    reason: str


def resolve_route(
    *,
    authority_valid: bool,
    primary_route: str,
    primary_available: bool,
    approved_secondaries: Sequence[tuple[str, bool]] = (),
) -> RouteDecision:
    if not authority_valid:
        return RouteDecision("INVALID", "UNKNOWN", None, False, "ROUTE_AUTHORITY_INVALID_RELOCK_REQUIRED")
    if primary_available:
        return RouteDecision("VALID", "UP", primary_route, False, "PRIMARY_AVAILABLE")
    for route, available in approved_secondaries:
        if available:
            return RouteDecision("VALID", "PRIMARY_DOWN_APPROVED_FALLBACK_UP", route, False, "APPROVED_ROUTE_SET_FAILOVER")
    return RouteDecision("VALID", "DOWN", None, False, "BLOCKED_NO_APPROVED_AVAILABLE_ROUTE")


@dataclass(frozen=True)
class ThemeClosureResult:
    complete: bool
    reason: str


def final_theme_closure(
    *,
    intent_receipt: IntentReceipt,
    actual_effect_observed: bool,
    done_when_satisfied: bool,
    unresolved_blockers: int,
) -> ThemeClosureResult:
    if intent_receipt.status != "ACTIVE":
        return ThemeClosureResult(False, "INTENT_RECEIPT_NOT_ACTIVE")
    if unresolved_blockers:
        return ThemeClosureResult(False, "UNRESOLVED_BLOCKER")
    if not actual_effect_observed:
        return ThemeClosureResult(False, "ACTUAL_EFFECT_NOT_OBSERVED")
    if not done_when_satisfied:
        return ThemeClosureResult(False, "DONE_WHEN_NOT_SATISFIED")
    return ThemeClosureResult(True, "FINAL_THEME_CLOSURE_PASS")


def unknown_recovery_packet(
    *,
    why_unknown: str,
    missing_evidence: Sequence[str],
    minimum_recovery_action: Sequence[str],
    forbidden_actions: Sequence[str],
) -> dict[str, object]:
    if not why_unknown.strip() or not missing_evidence or not minimum_recovery_action or not forbidden_actions:
        raise ValueError("UNKNOWN recovery requires reason/evidence/recovery/forbidden fields")
    return {
        "WHY_UNKNOWN": why_unknown.strip(),
        "WHAT_EVIDENCE_IS_MISSING": tuple(missing_evidence),
        "MINIMUM_RECOVERY_ACTION": tuple(minimum_recovery_action),
        "WHAT_MUST_NOT_BE_DONE": tuple(forbidden_actions),
    }


class MaterialClassification(str, Enum):
    MATERIAL = "MATERIAL"
    TRANSITIVE_MATERIAL = "TRANSITIVE_MATERIAL"
    READ_ONLY_NON_MATERIAL = "READ_ONLY_NON_MATERIAL"
    UNKNOWN = "UNKNOWN"


MATERIAL_PRIMITIVES: FrozenSet[str] = frozenset(
    {
        "fs_write",
        "fs_delete",
        "fs_rename",
        "fs_move",
        "fs_replace",
        "acl_mutation",
        "process_start",
        "process_stop",
        "process_kill",
        "service_mutation",
        "listener_mutation",
        "session_mutation",
        "vm_mutation",
        "dom_insert",
        "ui_input",
        "runtime_state_write",
        "repo_write",
        "repo_commit",
        "repo_push",
        "repo_merge",
        "repo_tag_mutation",
        "current_update",
        "dispatch_material",
        "runner_request",
        "control_inbox_write",
    }
)

READ_ONLY_PRIMITIVES: FrozenSet[str] = frozenset(
    {
        "fs_read",
        "list",
        "stat",
        "hash",
        "parse",
        "compare",
        "api_read",
        "log_read",
    }
)


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    primitives: tuple[str, ...] = ()
    children: tuple[str, ...] = ()
    read_only_proof: bool = False
    generic_exec: bool = False
    unresolved_external: bool = False


@dataclass(frozen=True)
class MaterialDecision:
    classification: MaterialClassification
    reason: str
    reachable_nodes: tuple[str, ...]
    graph_digest: str


def _primitive_kind(value: str) -> str:
    return str(value).split(":", 1)[0].strip().lower()


def execution_graph_digest(nodes: Mapping[str, ExecutionNode]) -> str:
    import hashlib
    import json

    normalized = []
    for key in sorted(nodes):
        node = nodes[key]
        normalized.append(
            {
                "key": key,
                "node_id": node.node_id,
                "primitives": sorted(str(x) for x in node.primitives),
                "children": sorted(str(x) for x in node.children),
                "read_only_proof": bool(node.read_only_proof),
                "generic_exec": bool(node.generic_exec),
                "unresolved_external": bool(node.unresolved_external),
            }
        )
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def classify_material_graph(nodes: Mapping[str, ExecutionNode], entry_id: str) -> MaterialDecision:
    digest = execution_graph_digest(nodes)
    if not entry_id or entry_id not in nodes:
        return MaterialDecision(MaterialClassification.UNKNOWN, "ENTRY_NOT_RESOLVED", (), digest)

    reachable: set[str] = set()
    missing_children: set[str] = set()
    stack = [entry_id]
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        node = nodes.get(current)
        if node is None:
            missing_children.add(current)
            continue
        reachable.add(current)
        for child in node.children:
            if child not in nodes:
                missing_children.add(child)
            elif child not in reachable:
                stack.append(child)

    direct_material = False
    descendant_material = False
    for node_id in reachable:
        node = nodes[node_id]
        has_material = any(_primitive_kind(value) in MATERIAL_PRIMITIVES for value in node.primitives)
        if node_id == entry_id and has_material:
            direct_material = True
        elif has_material:
            descendant_material = True

    ordered = tuple(sorted(reachable))
    if direct_material:
        return MaterialDecision(MaterialClassification.MATERIAL, "DIRECT_MATERIAL_PRIMITIVE", ordered, digest)
    if descendant_material:
        return MaterialDecision(MaterialClassification.TRANSITIVE_MATERIAL, "REACHABLE_MATERIAL_CHILD", ordered, digest)

    if missing_children:
        return MaterialDecision(MaterialClassification.UNKNOWN, "UNRESOLVED_CHILD_EDGE", ordered, digest)

    for node_id in reachable:
        node = nodes[node_id]
        if node.unresolved_external:
            return MaterialDecision(MaterialClassification.UNKNOWN, "UNRESOLVED_EXTERNAL_EXECUTION", ordered, digest)
        if node.generic_exec:
            return MaterialDecision(MaterialClassification.UNKNOWN, "GENERIC_EXEC_NOT_PROVEN_READ_ONLY", ordered, digest)
        primitive_kinds = {_primitive_kind(value) for value in node.primitives}
        if not primitive_kinds.issubset(READ_ONLY_PRIMITIVES):
            return MaterialDecision(MaterialClassification.UNKNOWN, "UNCLASSIFIED_PRIMITIVE", ordered, digest)
        if not node.read_only_proof:
            return MaterialDecision(MaterialClassification.UNKNOWN, "READ_ONLY_PROOF_MISSING", ordered, digest)

    return MaterialDecision(MaterialClassification.READ_ONLY_NON_MATERIAL, "CLOSED_READ_ONLY_GRAPH_PROVEN", ordered, digest)
