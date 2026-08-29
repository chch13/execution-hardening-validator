from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
from pathlib import Path

from execution_hardening_b0_infrastructure import (
    F10Adjudicator,
    FaultVerifier,
    InventoryBuilder,
    InventoryVerifier,
)

VARIANTS = 5
CASE_COUNT = 28
EXPECTED_TRIALS = CASE_COUNT * VARIANTS


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def git_blob(path: str) -> str:
    return subprocess.check_output(["git", "hash-object", path], text=True).strip()


def declarations(v: int) -> dict:
    return {
        "schema_version": "execution-hardening-b0-declarations/v1",
        "inventory_scope": {"route": f"R{v}", "claim": "B1 synthetic meta acceptance"},
        "source_roots": [
            {"path": f"root/b-{v}.txt", "identity": "blob:" + h(f"root-b-{v}")},
            {"path": f"root/a-{v}.txt", "identity": "blob:" + h(f"root-a-{v}")},
        ],
        "rows": [
            {
                "route_id": f"R{v}", "surface_id": f"S2-{v}", "component": "beta",
                "file_path": f"tools/b-{v}.py", "symbol": f"beta_{v}",
                "execution_class": "UNKNOWN", "entry_condition": f"entry-beta-{v}",
                "outcome": f"outcome-beta-{v}", "guard_or_proof": f"proof-beta-{v}",
                "provenance": {"source": f"fixture-beta-{v}", "identity": h(f"prov-beta-{v}")},
            },
            {
                "route_id": f"R{v}", "surface_id": f"S1-{v}", "component": "alpha",
                "file_path": f"tools/a-{v}.py", "symbol": f"alpha_{v}",
                "execution_class": "MATERIAL", "entry_condition": f"entry-alpha-{v}",
                "outcome": f"outcome-alpha-{v}", "guard_or_proof": f"proof-alpha-{v}",
                "provenance": {"source": f"fixture-alpha-{v}", "identity": h(f"prov-alpha-{v}")},
            },
        ],
    }


def fault_plan(v: int) -> dict:
    return {
        "schema_version": "execution-hardening-fault-plan/v1",
        "plan_id": f"PLAN-{v}",
        "cases": [
            {"case_id": f"BLOCK-{v}", "variants": 2, "expected_state": "BLOCKED"},
            {"case_id": f"ALLOW-{v}", "variants": 1, "expected_state": "PASS"},
        ],
    }


def fault_result(v: int) -> dict:
    return {
        "schema_version": "execution-hardening-fault-result/v1",
        "plan_id": f"PLAN-{v}",
        "trials": [
            {"case_id": f"BLOCK-{v}", "variant": 1, "observed_state": "BLOCKED", "critical_error": False, "evidence_sha256": h(f"ev-b1-{v}")},
            {"case_id": f"BLOCK-{v}", "variant": 2, "observed_state": "BLOCKED", "critical_error": False, "evidence_sha256": h(f"ev-b2-{v}")},
            {"case_id": f"ALLOW-{v}", "variant": 1, "observed_state": "PASS", "critical_error": False, "evidence_sha256": h(f"ev-a1-{v}")},
        ],
    }


def f10_policy(v: int) -> dict:
    gates = [f"G1-{v}", f"G2-{v}", f"G3-{v}"]
    return {
        "schema_version": "execution-hardening-f10-policy/v1",
        "policy_id": f"POLICY-{v}",
        "required_gates": gates,
        "required_state": "PASS",
        "allow_extra_gates": False,
        "expected_receipt_sha256": {},
    }


def f10_bundle(v: int) -> dict:
    return {
        "schema_version": "execution-hardening-f10-bundle/v1",
        "policy_id": f"POLICY-{v}",
        "receipts": [
            {"gate_id": f"G1-{v}", "state": "PASS", "receipt_sha256": h(f"g1-{v}"), "claim_boundary": f"boundary-1-{v}"},
            {"gate_id": f"G2-{v}", "state": "PASS", "receipt_sha256": h(f"g2-{v}"), "claim_boundary": f"boundary-2-{v}"},
            {"gate_id": f"G3-{v}", "state": "PASS", "receipt_sha256": h(f"g3-{v}"), "claim_boundary": f"boundary-3-{v}"},
        ],
    }


def must_fail(callable_, label: str) -> None:
    try:
        callable_()
    except Exception:
        return
    raise AssertionError(f"expected fail-closed exception: {label}")


def expect_state(result: dict, expected: str, label: str) -> None:
    if result.get("state") != expected:
        raise AssertionError(f"{label}: expected {expected}, got {result.get('state')} errors={result.get('errors')}")


def i01_determinism(v: int) -> None:
    d = declarations(v)
    if InventoryBuilder.build(d) != InventoryBuilder.build(copy.deepcopy(d)):
        raise AssertionError("inventory nondeterministic")


def i02_row_order_invariance(v: int) -> None:
    a = declarations(v); b = copy.deepcopy(a); b["rows"].reverse()
    if InventoryBuilder.build(a) != InventoryBuilder.build(b):
        raise AssertionError("row order changed canonical inventory")


def i03_root_order_invariance(v: int) -> None:
    a = declarations(v); b = copy.deepcopy(a); b["source_roots"].reverse()
    if InventoryBuilder.build(a) != InventoryBuilder.build(b):
        raise AssertionError("source-root order changed canonical inventory")


def i04_missing_field_rejected(v: int) -> None:
    d = declarations(v); del d["rows"][0]["guard_or_proof"]
    must_fail(lambda: InventoryBuilder.build(d), "missing row field")


def i05_extra_field_rejected(v: int) -> None:
    d = declarations(v); d["rows"][0]["invented"] = f"x-{v}"
    must_fail(lambda: InventoryBuilder.build(d), "extra row field")


def i06_duplicate_identity_rejected(v: int) -> None:
    d = declarations(v); d["rows"].append(copy.deepcopy(d["rows"][0]))
    must_fail(lambda: InventoryBuilder.build(d), "duplicate row identity")


def i07_invalid_class_rejected(v: int) -> None:
    d = declarations(v); d["rows"][0]["execution_class"] = f"ASSUMED_SAFE_{v}"
    must_fail(lambda: InventoryBuilder.build(d), "invalid execution class")


def i08_empty_provenance_rejected(v: int) -> None:
    d = declarations(v); d["rows"][0]["provenance"] = {}
    must_fail(lambda: InventoryBuilder.build(d), "empty provenance")


def v01_exact_inventory_passes(v: int) -> None:
    d = declarations(v); artifact = InventoryBuilder.build(d)
    expect_state(InventoryVerifier.verify(d, artifact), "PASS", "exact inventory")


def v02_tampered_inventory_fails(v: int) -> None:
    d = declarations(v); artifact = InventoryBuilder.build(d); artifact["rows"][0]["outcome"] += "-tamper"
    expect_state(InventoryVerifier.verify(d, artifact), "FAIL", "tampered inventory")


def v03_undeclared_artifact_field_fails(v: int) -> None:
    d = declarations(v); artifact = InventoryBuilder.build(d); artifact[f"extra_{v}"] = True
    expect_state(InventoryVerifier.verify(d, artifact), "FAIL", "extra artifact field")


def f01_exact_fault_universe_passes(v: int) -> None:
    expect_state(FaultVerifier.verify(fault_plan(v), fault_result(v)), "PASS", "exact fault universe")


def f02_missing_trial_fails(v: int) -> None:
    r = fault_result(v); r["trials"].pop()
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "missing trial")


def f03_extra_trial_fails(v: int) -> None:
    r = fault_result(v); r["trials"].append({"case_id": f"EXTRA-{v}", "variant": 1, "observed_state": "PASS", "critical_error": False, "evidence_sha256": h(f"extra-{v}")})
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "extra trial")


def f04_duplicate_trial_fails(v: int) -> None:
    r = fault_result(v); r["trials"].append(copy.deepcopy(r["trials"][0]))
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "duplicate trial")


def f05_wrong_state_fails(v: int) -> None:
    r = fault_result(v); r["trials"][0]["observed_state"] = "PASS"
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "wrong state")


def f06_unknown_critical_state_fails(v: int) -> None:
    r = fault_result(v); r["trials"][0]["critical_error"] = None
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "unknown critical state")


def f07_invalid_evidence_hash_fails(v: int) -> None:
    r = fault_result(v); r["trials"][0]["evidence_sha256"] = f"not-a-sha-{v}"
    expect_state(FaultVerifier.verify(fault_plan(v), r), "FAIL", "invalid evidence sha")


def a01_exact_gate_bundle_passes(v: int) -> None:
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), f10_bundle(v)), "PASS", "exact gate bundle")


def a02_missing_gate_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"].pop()
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "missing gate")


def a03_extra_gate_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"].append({"gate_id": f"EXTRA-{v}", "state": "PASS", "receipt_sha256": h(f"extra-gate-{v}"), "claim_boundary": "extra"})
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "extra gate")


def a04_duplicate_gate_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"].append(copy.deepcopy(b["receipts"][0]))
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "duplicate gate")


def a05_wrong_gate_state_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"][1]["state"] = "UNKNOWN"
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "wrong/unknown gate state")


def a06_missing_boundary_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"][1]["claim_boundary"] = ""
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "missing boundary")


def a07_invalid_receipt_sha_fails(v: int) -> None:
    b = f10_bundle(v); b["receipts"][1]["receipt_sha256"] = f"bad-{v}"
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "invalid receipt sha")


def a08_expected_hash_mismatch_fails(v: int) -> None:
    p = f10_policy(v); p["expected_receipt_sha256"] = {f"G1-{v}": h(f"wrong-{v}")}
    expect_state(F10Adjudicator.adjudicate(p, f10_bundle(v)), "FAIL", "expected receipt hash mismatch")


def a09_receipt_order_invariant(v: int) -> None:
    p = f10_policy(v); a = f10_bundle(v); b = copy.deepcopy(a); b["receipts"].reverse()
    if F10Adjudicator.adjudicate(p, a)["state"] != F10Adjudicator.adjudicate(p, b)["state"]:
        raise AssertionError("receipt order changed adjudication state")
    if F10Adjudicator.adjudicate(p, a)["state"] != "PASS":
        raise AssertionError("baseline order-invariance bundle not PASS")


def a10_policy_id_mismatch_fails(v: int) -> None:
    b = f10_bundle(v); b["policy_id"] = f"OTHER-{v}"
    expect_state(F10Adjudicator.adjudicate(f10_policy(v), b), "FAIL", "policy id mismatch")


CASES = [
    ("I01_DETERMINISM", i01_determinism),
    ("I02_ROW_ORDER_INVARIANCE", i02_row_order_invariance),
    ("I03_ROOT_ORDER_INVARIANCE", i03_root_order_invariance),
    ("I04_MISSING_FIELD_REJECTED", i04_missing_field_rejected),
    ("I05_EXTRA_FIELD_REJECTED", i05_extra_field_rejected),
    ("I06_DUPLICATE_IDENTITY_REJECTED", i06_duplicate_identity_rejected),
    ("I07_INVALID_CLASS_REJECTED", i07_invalid_class_rejected),
    ("I08_EMPTY_PROVENANCE_REJECTED", i08_empty_provenance_rejected),
    ("V01_EXACT_INVENTORY_PASS", v01_exact_inventory_passes),
    ("V02_TAMPER_FAIL", v02_tampered_inventory_fails),
    ("V03_EXTRA_ARTIFACT_FIELD_FAIL", v03_undeclared_artifact_field_fails),
    ("F01_EXACT_FAULT_UNIVERSE_PASS", f01_exact_fault_universe_passes),
    ("F02_MISSING_TRIAL_FAIL", f02_missing_trial_fails),
    ("F03_EXTRA_TRIAL_FAIL", f03_extra_trial_fails),
    ("F04_DUPLICATE_TRIAL_FAIL", f04_duplicate_trial_fails),
    ("F05_WRONG_STATE_FAIL", f05_wrong_state_fails),
    ("F06_UNKNOWN_CRITICAL_FAIL", f06_unknown_critical_state_fails),
    ("F07_INVALID_EVIDENCE_SHA_FAIL", f07_invalid_evidence_hash_fails),
    ("A01_EXACT_GATE_BUNDLE_PASS", a01_exact_gate_bundle_passes),
    ("A02_MISSING_GATE_FAIL", a02_missing_gate_fails),
    ("A03_EXTRA_GATE_FAIL", a03_extra_gate_fails),
    ("A04_DUPLICATE_GATE_FAIL", a04_duplicate_gate_fails),
    ("A05_UNKNOWN_GATE_STATE_FAIL", a05_wrong_gate_state_fails),
    ("A06_MISSING_BOUNDARY_FAIL", a06_missing_boundary_fails),
    ("A07_INVALID_RECEIPT_SHA_FAIL", a07_invalid_receipt_sha_fails),
    ("A08_EXPECTED_HASH_MISMATCH_FAIL", a08_expected_hash_mismatch_fails),
    ("A09_RECEIPT_ORDER_INVARIANT", a09_receipt_order_invariant),
    ("A10_POLICY_ID_MISMATCH_FAIL", a10_policy_id_mismatch_fails),
]


def run() -> dict:
    failures: list[str] = []
    executed = 0
    for name, fn in CASES:
        for variant in range(1, VARIANTS + 1):
            executed += 1
            try:
                fn(variant)
            except Exception as exc:
                failures.append(f"{name}[{variant}]: {exc}")
    if len(CASES) != CASE_COUNT:
        failures.append(f"case count mismatch {len(CASES)} != {CASE_COUNT}")
    if executed != EXPECTED_TRIALS:
        failures.append(f"trial count mismatch {executed} != {EXPECTED_TRIALS}")
    result = {
        "schema_version": "execution-hardening-b1-meta-acceptance-receipt/v1",
        "state": "PASS" if not failures else "FAIL",
        "production_binding": "tools/execution_hardening_b0_infrastructure.py",
        "production_blob_sha": git_blob("tools/execution_hardening_b0_infrastructure.py"),
        "meta_harness": "tools/execution_hardening_b1_meta_acceptance.py",
        "meta_harness_blob_sha": git_blob("tools/execution_hardening_b1_meta_acceptance.py"),
        "case_count": len(CASES),
        "variants_per_case": VARIANTS,
        "expected_trials": EXPECTED_TRIALS,
        "executed_trials": executed,
        "passed_trials": executed - len(failures),
        "failed_trials": len(failures),
        "critical_errors": len(failures),
        "failures": failures,
        "claim_boundary": "B1 production-bound B0 mechanism meta acceptance only; does not prove C0 inventory completeness, C1/F10, F01-F09, or final execution hardening",
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="b1_meta_acceptance_receipt.json")
    args = parser.parse_args()
    result = run()
    Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if result["state"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
