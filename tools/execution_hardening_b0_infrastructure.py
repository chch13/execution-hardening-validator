from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

DECLARATIONS_SCHEMA = "execution-hardening-b0-declarations/v1"
INVENTORY_SCHEMA = "execution-hardening-b0-inventory/v1"
INVENTORY_VERIFIER_SCHEMA = "execution-hardening-b0-inventory-verifier-receipt/v1"
FAULT_PLAN_SCHEMA = "execution-hardening-fault-plan/v1"
FAULT_RESULT_SCHEMA = "execution-hardening-fault-result/v1"
FAULT_VERIFIER_SCHEMA = "execution-hardening-fault-verifier-receipt/v1"
F10_POLICY_SCHEMA = "execution-hardening-f10-policy/v1"
F10_BUNDLE_SCHEMA = "execution-hardening-f10-bundle/v1"
F10_RECEIPT_SCHEMA = "execution-hardening-f10-adjudication-receipt/v1"

BUILDER_VERSION = "execution-hardening-inventory-builder/v1"
INVENTORY_VERIFIER_VERSION = "execution-hardening-inventory-verifier/v1"
FAULT_VERIFIER_VERSION = "execution-hardening-fault-verifier/v1"
F10_ADJUDICATOR_VERSION = "execution-hardening-f10-adjudicator/v1"

ALLOWED_EXECUTION_CLASSES = frozenset({
    "MATERIAL",
    "TRANSITIVE_MATERIAL",
    "READ_ONLY_NON_MATERIAL",
    "UNKNOWN",
})
REQUIRED_ROW_FIELDS = (
    "route_id",
    "surface_id",
    "component",
    "file_path",
    "symbol",
    "execution_class",
    "entry_condition",
    "outcome",
    "guard_or_proof",
    "provenance",
)
ORDERING_RULE = "route_id,surface_id,component,file_path,symbol,row_id:unicode-codepoint-ascending"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field}: non-empty string required")
    return value.strip()


def _normalized_source_roots(raw_roots: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_roots, list) or not raw_roots:
        raise ValueError("source_roots: non-empty list required")
    roots: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_roots):
        if not isinstance(raw, Mapping):
            raise ValueError(f"source_roots[{index}]: object required")
        item = dict(raw)
        item["path"] = _text(raw.get("path"), f"source_roots[{index}].path")
        item["identity"] = _text(raw.get("identity"), f"source_roots[{index}].identity")
        key = (item["path"], item["identity"])
        if key in seen:
            raise ValueError("duplicate source root")
        seen.add(key)
        roots.append(item)
    roots.sort(key=lambda x: (x["path"], x["identity"], canonical_bytes(x)))
    return roots


def _normalized_rows(raw_rows: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("rows: non-empty list required")
    rows: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str, str, str]] = set()
    row_ids: set[str] = set()
    required = set(REQUIRED_ROW_FIELDS)
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping):
            raise ValueError(f"rows[{index}]: object required")
        if set(raw) != required:
            missing = sorted(required - set(raw))
            extra = sorted(set(raw) - required)
            raise ValueError(f"rows[{index}]: field set mismatch missing={missing} extra={extra}")
        row: dict[str, Any] = {}
        for field in REQUIRED_ROW_FIELDS:
            value = raw[field]
            if field == "provenance":
                if not isinstance(value, Mapping) or not value:
                    raise ValueError(f"rows[{index}].provenance: non-empty object required")
                row[field] = dict(value)
            else:
                row[field] = _text(value, f"rows[{index}].{field}")
        if row["execution_class"] not in ALLOWED_EXECUTION_CLASSES:
            raise ValueError(f"rows[{index}].execution_class invalid")
        identity = (row["route_id"], row["surface_id"], row["component"], row["file_path"], row["symbol"])
        if identity in identities:
            raise ValueError("duplicate route/surface/component/file/symbol identity")
        identities.add(identity)
        row_id = "ROW-" + sha256_hex(row)[:24]
        if row_id in row_ids:
            raise ValueError("row_id collision/duplicate content")
        row_ids.add(row_id)
        row["row_id"] = row_id
        rows.append(row)
    rows.sort(key=lambda r: (r["route_id"], r["surface_id"], r["component"], r["file_path"], r["symbol"], r["row_id"]))
    return rows


def _expected_inventory(declarations: Mapping[str, Any]) -> dict[str, Any]:
    if declarations.get("schema_version") != DECLARATIONS_SCHEMA:
        raise ValueError("declarations schema mismatch")
    scope = declarations.get("inventory_scope")
    if not isinstance(scope, Mapping) or not scope:
        raise ValueError("inventory_scope: non-empty object required")
    roots = _normalized_source_roots(declarations.get("source_roots"))
    rows = _normalized_rows(declarations.get("rows"))
    core = {
        "schema_version": INVENTORY_SCHEMA,
        "builder_version": BUILDER_VERSION,
        "inventory_scope": dict(scope),
        "source_roots": roots,
        "ordering_rule": ORDERING_RULE,
        "rows": rows,
    }
    core_sha = sha256_hex(core)
    inventory_id = "INV-" + core_sha[:24]
    rows_with_inventory = [{"inventory_id": inventory_id, **row} for row in rows]
    no_hash = {
        "schema_version": INVENTORY_SCHEMA,
        "builder_version": BUILDER_VERSION,
        "inventory_id": inventory_id,
        "inventory_scope": dict(scope),
        "source_roots": roots,
        "ordering_rule": ORDERING_RULE,
        "row_count": len(rows_with_inventory),
        "inventory_core_sha256": core_sha,
        "rows": rows_with_inventory,
    }
    return {**no_hash, "artifact_sha256": sha256_hex(no_hash)}


class InventoryBuilder:
    """Deterministically canonicalize already-declared B0 rows; never invent missing semantics."""

    @staticmethod
    def build(declarations: Mapping[str, Any]) -> dict[str, Any]:
        return _expected_inventory(declarations)


class InventoryVerifier:
    """Re-derive the exact inventory envelope and fail closed on any mismatch/tamper."""

    @staticmethod
    def verify(declarations: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, Any]:
        try:
            expected = _expected_inventory(declarations)
        except Exception as exc:
            return {
                "schema_version": INVENTORY_VERIFIER_SCHEMA,
                "verifier_version": INVENTORY_VERIFIER_VERSION,
                "state": "FAIL",
                "errors": [f"DECLARATIONS_INVALID:{exc}"],
            }
        errors: list[str] = []
        for key, value in expected.items():
            if artifact.get(key) != value:
                errors.append(f"ARTIFACT_MISMATCH:{key}")
        extra = set(artifact) - set(expected)
        if extra:
            errors.append(f"ARTIFACT_UNDECLARED_FIELDS:{sorted(extra)}")
        if not HEX64.match(str(artifact.get("artifact_sha256", ""))):
            errors.append("ARTIFACT_SHA_FORMAT_INVALID")
        if not HEX64.match(str(artifact.get("inventory_core_sha256", ""))):
            errors.append("CORE_SHA_FORMAT_INVALID")
        return {
            "schema_version": INVENTORY_VERIFIER_SCHEMA,
            "verifier_version": INVENTORY_VERIFIER_VERSION,
            "state": "PASS" if not errors else "FAIL",
            "errors": errors,
            "inventory_id": expected["inventory_id"],
            "row_count": expected["row_count"],
            "artifact_sha256": expected["artifact_sha256"],
            "declarations_sha256": sha256_hex(declarations),
        }


class FaultVerifier:
    """Verify exact trial coverage/outcomes against an explicit fault plan; UNKNOWN never passes."""

    @staticmethod
    def verify(plan: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        if plan.get("schema_version") != FAULT_PLAN_SCHEMA:
            errors.append("PLAN_SCHEMA_MISMATCH")
        if result.get("schema_version") != FAULT_RESULT_SCHEMA:
            errors.append("RESULT_SCHEMA_MISMATCH")
        plan_id = plan.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id.strip():
            errors.append("PLAN_ID_MISSING")
        if result.get("plan_id") != plan_id:
            errors.append("PLAN_ID_MISMATCH")

        expected: dict[tuple[str, int], str] = {}
        cases = plan.get("cases")
        if not isinstance(cases, list) or not cases:
            errors.append("PLAN_CASES_MISSING")
            cases = []
        for index, case in enumerate(cases):
            if not isinstance(case, Mapping):
                errors.append(f"PLAN_CASE_NOT_OBJECT:{index}")
                continue
            case_id = case.get("case_id")
            variants = case.get("variants")
            expected_state = case.get("expected_state")
            if not isinstance(case_id, str) or not case_id.strip():
                errors.append(f"PLAN_CASE_ID_INVALID:{index}")
                continue
            if not isinstance(variants, int) or variants < 1:
                errors.append(f"PLAN_VARIANTS_INVALID:{case_id}")
                continue
            if not isinstance(expected_state, str) or not expected_state.strip():
                errors.append(f"PLAN_EXPECTED_STATE_INVALID:{case_id}")
                continue
            for variant in range(1, variants + 1):
                key = (case_id, variant)
                if key in expected:
                    errors.append(f"PLAN_DUPLICATE_TRIAL:{case_id}:{variant}")
                expected[key] = expected_state

        observed: dict[tuple[str, int], Mapping[str, Any]] = {}
        trials = result.get("trials")
        if not isinstance(trials, list):
            errors.append("RESULT_TRIALS_MISSING")
            trials = []
        for index, trial in enumerate(trials):
            if not isinstance(trial, Mapping):
                errors.append(f"TRIAL_NOT_OBJECT:{index}")
                continue
            case_id = trial.get("case_id")
            variant = trial.get("variant")
            if not isinstance(case_id, str) or not isinstance(variant, int):
                errors.append(f"TRIAL_ID_INVALID:{index}")
                continue
            key = (case_id, variant)
            if key in observed:
                errors.append(f"DUPLICATE_TRIAL:{case_id}:{variant}")
                continue
            observed[key] = trial

        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        if missing:
            errors.append("MISSING_TRIALS:" + ",".join(f"{c}:{v}" for c, v in missing))
        if extra:
            errors.append("EXTRA_TRIALS:" + ",".join(f"{c}:{v}" for c, v in extra))
        for key in sorted(set(expected) & set(observed)):
            trial = observed[key]
            if trial.get("observed_state") != expected[key]:
                errors.append(f"STATE_MISMATCH:{key[0]}:{key[1]}")
            if trial.get("critical_error") is not False:
                errors.append(f"CRITICAL_ERROR_OR_UNKNOWN:{key[0]}:{key[1]}")
            evidence_sha = trial.get("evidence_sha256")
            if not isinstance(evidence_sha, str) or not HEX64.match(evidence_sha):
                errors.append(f"EVIDENCE_SHA_INVALID:{key[0]}:{key[1]}")
        return {
            "schema_version": FAULT_VERIFIER_SCHEMA,
            "verifier_version": FAULT_VERIFIER_VERSION,
            "state": "PASS" if not errors else "FAIL",
            "errors": errors,
            "plan_id": plan_id,
            "expected_trial_count": len(expected),
            "observed_trial_count": len(observed),
            "plan_sha256": sha256_hex(plan),
            "result_sha256": sha256_hex(result),
        }


class F10Adjudicator:
    """Adjudicate an explicit required gate set; no missing/failed/unknown receipt can be promoted to PASS."""

    @staticmethod
    def adjudicate(policy: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        if policy.get("schema_version") != F10_POLICY_SCHEMA:
            errors.append("POLICY_SCHEMA_MISMATCH")
        if bundle.get("schema_version") != F10_BUNDLE_SCHEMA:
            errors.append("BUNDLE_SCHEMA_MISMATCH")
        policy_id = policy.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            errors.append("POLICY_ID_MISSING")
        if bundle.get("policy_id") != policy_id:
            errors.append("POLICY_ID_MISMATCH")

        required = policy.get("required_gates")
        if not isinstance(required, list) or not required or any(not isinstance(x, str) or not x.strip() for x in required):
            errors.append("REQUIRED_GATES_INVALID")
            required = []
        if len(set(required)) != len(required):
            errors.append("REQUIRED_GATES_DUPLICATE")
        required_state = policy.get("required_state", "PASS")
        if not isinstance(required_state, str) or not required_state.strip():
            errors.append("REQUIRED_STATE_INVALID")
        expected_hashes = policy.get("expected_receipt_sha256", {})
        if not isinstance(expected_hashes, Mapping):
            errors.append("EXPECTED_HASHES_INVALID")
            expected_hashes = {}
        allow_extra = policy.get("allow_extra_gates", False)
        if not isinstance(allow_extra, bool):
            errors.append("ALLOW_EXTRA_GATES_INVALID")
            allow_extra = False

        receipts = bundle.get("receipts")
        if not isinstance(receipts, list):
            errors.append("RECEIPTS_MISSING")
            receipts = []
        by_gate: dict[str, Mapping[str, Any]] = {}
        for index, receipt in enumerate(receipts):
            if not isinstance(receipt, Mapping):
                errors.append(f"RECEIPT_NOT_OBJECT:{index}")
                continue
            gate_id = receipt.get("gate_id")
            if not isinstance(gate_id, str) or not gate_id.strip():
                errors.append(f"GATE_ID_INVALID:{index}")
                continue
            if gate_id in by_gate:
                errors.append(f"DUPLICATE_GATE:{gate_id}")
                continue
            by_gate[gate_id] = receipt

        missing = sorted(set(required) - set(by_gate))
        extra = sorted(set(by_gate) - set(required))
        if missing:
            errors.append("MISSING_GATES:" + ",".join(missing))
        if extra and not allow_extra:
            errors.append("EXTRA_GATES:" + ",".join(extra))
        for gate_id in required:
            receipt = by_gate.get(gate_id)
            if receipt is None:
                continue
            if receipt.get("state") != required_state:
                errors.append(f"GATE_STATE_MISMATCH:{gate_id}")
            receipt_sha = receipt.get("receipt_sha256")
            if not isinstance(receipt_sha, str) or not HEX64.match(receipt_sha):
                errors.append(f"RECEIPT_SHA_INVALID:{gate_id}")
            expected_sha = expected_hashes.get(gate_id)
            if expected_sha is not None and receipt_sha != expected_sha:
                errors.append(f"RECEIPT_SHA_MISMATCH:{gate_id}")
            claim_boundary = receipt.get("claim_boundary")
            if not isinstance(claim_boundary, str) or not claim_boundary.strip():
                errors.append(f"CLAIM_BOUNDARY_MISSING:{gate_id}")
        return {
            "schema_version": F10_RECEIPT_SCHEMA,
            "adjudicator_version": F10_ADJUDICATOR_VERSION,
            "state": "PASS" if not errors else "FAIL",
            "errors": errors,
            "policy_id": policy_id,
            "required_gate_count": len(required),
            "observed_gate_count": len(by_gate),
            "policy_sha256": sha256_hex(policy),
            "bundle_sha256": sha256_hex(bundle),
        }
