from __future__ import annotations

import copy
import hashlib

from execution_hardening_b0_infrastructure import F10Adjudicator, FaultVerifier, InventoryBuilder, InventoryVerifier


def h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def declarations() -> dict:
    return {
        "schema_version": "execution-hardening-b0-declarations/v1",
        "inventory_scope": {"claim": "synthetic self-test only", "route": "ROUTE-A"},
        "source_roots": [
            {"path": "tools/a.py", "identity": "blob:" + h("a")},
            {"path": "workflow.yml", "identity": "blob:" + h("w")},
        ],
        "rows": [
            {"route_id": "ROUTE-A", "surface_id": "SURFACE-2", "component": "component-b", "file_path": "tools/a.py", "symbol": "b", "execution_class": "UNKNOWN", "entry_condition": "condition-b", "outcome": "outcome-b", "guard_or_proof": "proof-b", "provenance": {"ref": "tools/a.py#b"}},
            {"route_id": "ROUTE-A", "surface_id": "SURFACE-1", "component": "component-a", "file_path": "tools/a.py", "symbol": "a", "execution_class": "MATERIAL", "entry_condition": "condition-a", "outcome": "outcome-a", "guard_or_proof": "proof-a", "provenance": {"ref": "tools/a.py#a"}},
        ],
    }


def expect_exception(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        return
    raise AssertionError(f"expected exception: {label}")


def inventory_tests() -> int:
    count = 0
    d = declarations()
    a = InventoryBuilder.build(d)
    if a != InventoryBuilder.build(copy.deepcopy(d)):
        raise AssertionError("builder is nondeterministic")
    count += 1
    if [r["surface_id"] for r in a["rows"]] != ["SURFACE-1", "SURFACE-2"]:
        raise AssertionError("stable ordering failed")
    count += 1
    if InventoryVerifier.verify(d, a)["state"] != "PASS":
        raise AssertionError("exact inventory failed verification")
    count += 1
    tampered = copy.deepcopy(a)
    tampered["rows"][0]["outcome"] = "tampered"
    if InventoryVerifier.verify(d, tampered)["state"] != "FAIL":
        raise AssertionError("tampered inventory passed")
    count += 1
    bad = declarations(); del bad["rows"][0]["provenance"]
    expect_exception(lambda: InventoryBuilder.build(bad), "missing provenance")
    count += 1
    bad = declarations(); bad["rows"][0]["execution_class"] = "SAFE_BECAUSE_NAME_SAYS_SO"
    expect_exception(lambda: InventoryBuilder.build(bad), "unknown execution class")
    count += 1
    bad = declarations(); bad["rows"].append(copy.deepcopy(bad["rows"][0]))
    expect_exception(lambda: InventoryBuilder.build(bad), "duplicate row")
    count += 1
    bad = declarations(); bad["rows"][0]["extra"] = "invented"
    expect_exception(lambda: InventoryBuilder.build(bad), "undeclared field")
    count += 1
    return count


def fault_tests() -> int:
    count = 0
    plan = {"schema_version": "execution-hardening-fault-plan/v1", "plan_id": "PLAN-1", "cases": [{"case_id": "C1", "variants": 2, "expected_state": "BLOCKED"}, {"case_id": "C2", "variants": 1, "expected_state": "PASS"}]}
    result = {"schema_version": "execution-hardening-fault-result/v1", "plan_id": "PLAN-1", "trials": [
        {"case_id": "C1", "variant": 1, "observed_state": "BLOCKED", "critical_error": False, "evidence_sha256": h("1")},
        {"case_id": "C1", "variant": 2, "observed_state": "BLOCKED", "critical_error": False, "evidence_sha256": h("2")},
        {"case_id": "C2", "variant": 1, "observed_state": "PASS", "critical_error": False, "evidence_sha256": h("3")},
    ]}
    if FaultVerifier.verify(plan, result)["state"] != "PASS": raise AssertionError("exact fault matrix failed")
    count += 1
    x = copy.deepcopy(result); x["trials"].pop()
    if FaultVerifier.verify(plan, x)["state"] != "FAIL": raise AssertionError("missing trial passed")
    count += 1
    x = copy.deepcopy(result); x["trials"][0]["observed_state"] = "PASS"
    if FaultVerifier.verify(plan, x)["state"] != "FAIL": raise AssertionError("wrong state passed")
    count += 1
    x = copy.deepcopy(result); x["trials"][0]["critical_error"] = None
    if FaultVerifier.verify(plan, x)["state"] != "FAIL": raise AssertionError("unknown critical error passed")
    count += 1
    x = copy.deepcopy(result); x["trials"].append({"case_id": "C9", "variant": 1, "observed_state": "PASS", "critical_error": False, "evidence_sha256": h("9")})
    if FaultVerifier.verify(plan, x)["state"] != "FAIL": raise AssertionError("extra trial passed")
    count += 1
    return count


def f10_tests() -> int:
    count = 0
    gates = [f"F{i:02d}" for i in range(1, 11)]
    policy = {"schema_version": "execution-hardening-f10-policy/v1", "policy_id": "F10-POLICY-SELFTEST", "required_gates": gates, "required_state": "PASS", "allow_extra_gates": False, "expected_receipt_sha256": {}}
    bundle = {"schema_version": "execution-hardening-f10-bundle/v1", "policy_id": "F10-POLICY-SELFTEST", "receipts": [{"gate_id": gate, "state": "PASS", "receipt_sha256": h(gate), "claim_boundary": "synthetic"} for gate in gates]}
    if F10Adjudicator.adjudicate(policy, bundle)["state"] != "PASS": raise AssertionError("exact F01-F10 bundle failed")
    count += 1
    x = copy.deepcopy(bundle); x["receipts"].pop()
    if F10Adjudicator.adjudicate(policy, x)["state"] != "FAIL": raise AssertionError("missing F gate passed")
    count += 1
    x = copy.deepcopy(bundle); x["receipts"][3]["state"] = "FAIL"
    if F10Adjudicator.adjudicate(policy, x)["state"] != "FAIL": raise AssertionError("failed F gate passed")
    count += 1
    x = copy.deepcopy(bundle); x["receipts"][2]["claim_boundary"] = ""
    if F10Adjudicator.adjudicate(policy, x)["state"] != "FAIL": raise AssertionError("missing boundary passed")
    count += 1
    p = copy.deepcopy(policy); p["expected_receipt_sha256"] = {"F01": h("different")}
    if F10Adjudicator.adjudicate(p, bundle)["state"] != "FAIL": raise AssertionError("receipt hash mismatch passed")
    count += 1
    return count


def main() -> None:
    inventory = inventory_tests(); fault = fault_tests(); f10 = f10_tests(); total = inventory + fault + f10
    print("EXECUTION_HARDENING_B0_INFRA_SELF_TEST_PASS")
    print(f"INVENTORY_TESTS={inventory}")
    print(f"FAULT_VERIFIER_TESTS={fault}")
    print(f"F10_ADJUDICATOR_TESTS={f10}")
    print(f"TOTAL_TESTS={total}")
    print("CRITICAL_ERRORS=0")
    print("CLAIM_BOUNDARY=B0 infrastructure behavior only; exact recovered B0 content inventory not yet claimed")


if __name__ == "__main__":
    main()
