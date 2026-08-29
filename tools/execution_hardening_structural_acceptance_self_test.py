from __future__ import annotations

import copy

from execution_hardening_structural_acceptance import (
    EXPECTED_A1_SOURCE_BLOBS,
    validate_a1_receipt,
    validate_b0_receipt,
    validate_private_pointer,
)


def expect_fail(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        return
    raise AssertionError(f"expected failure: {label}")


def valid_pointer() -> str:
    return """name: Execution Hardening Acceptance - Public Validator Pointer
on:
  workflow_dispatch:
jobs:
  public-validator-pointer:
    if: ${{ false }}
    runs-on: ubuntu-latest
    steps:
      - name: Public validator is authoritative
        run: echo \"Use chch13/execution-hardening-validator\"
# Do not substitute self-hosted execution for A1
# audits/EXECUTION_HARDENING_A1_PUBLIC_CURRENT.json
"""


def valid_a1() -> dict:
    return {
        "state": "PASS",
        "acceptance": "A1_MATERIAL_PREDICATE",
        "route_mode": "PUBLIC_GITHUB_HOSTED_VALIDATOR",
        "self_hosted_substitution_for_a1": False,
        "unknown_result_count": 0,
        "fixture_trials": {"executed": 65, "passed": 65, "failed": 0},
        "metamorphic_trials": {"executed": 30, "passed": 30, "failed": 0},
        "source_blob_shas": dict(EXPECTED_A1_SOURCE_BLOBS),
    }


def valid_b0() -> dict:
    return {
        "state": "PASS",
        "claim": "B0_INFRASTRUCTURE_BEHAVIOR_ONLY",
        "b0_exact_content_contract_status": "UNKNOWN_NOT_RECOVERED_FROM_CURRENT_REPOSITORY",
        "b0_canonical_content_inventory_status": "NOT_YET_BUILT",
        "whole_execution_hardening_complete": False,
    }


def main() -> None:
    tests = 0

    validate_private_pointer(valid_pointer()); tests += 1
    expect_fail(lambda: validate_private_pointer(valid_pointer().replace("workflow_dispatch:\n", "push:\n")), "push trigger accepted"); tests += 1
    expect_fail(lambda: validate_private_pointer(valid_pointer().replace("    if: ${{ false }}\n", "")), "active pointer job accepted"); tests += 1
    expect_fail(lambda: validate_private_pointer(valid_pointer().replace("    steps:\n", "    steps:\n      - uses: actions/checkout@v4\n")), "checkout in pointer accepted"); tests += 1

    a1 = valid_a1()
    validate_a1_receipt(a1, EXPECTED_A1_SOURCE_BLOBS); tests += 1
    x = copy.deepcopy(a1); x["self_hosted_substitution_for_a1"] = True
    expect_fail(lambda: validate_a1_receipt(x, EXPECTED_A1_SOURCE_BLOBS), "self-hosted substitution accepted"); tests += 1
    x = copy.deepcopy(a1); x["fixture_trials"]["passed"] = 64
    expect_fail(lambda: validate_a1_receipt(x, EXPECTED_A1_SOURCE_BLOBS), "64/65 fixture receipt accepted"); tests += 1
    wrong_blobs = dict(EXPECTED_A1_SOURCE_BLOBS); wrong_blobs["tools/execution_hardening_kernel.py"] = "0" * 40
    expect_fail(lambda: validate_a1_receipt(a1, wrong_blobs), "local source blob drift accepted"); tests += 1

    b0 = valid_b0()
    validate_b0_receipt(b0); tests += 1
    x = copy.deepcopy(b0); x["b0_canonical_content_inventory_status"] = "PASS"
    expect_fail(lambda: validate_b0_receipt(x), "premature B0 content promotion accepted"); tests += 1

    print("EXECUTION_HARDENING_STRUCTURAL_ROUTE_SELF_TEST_PASS")
    print(f"TOTAL_TESTS={tests}")
    print("CRITICAL_ERRORS=0")
    print("STRUCTURAL_ROUTE_MODE=PUBLIC_VALIDATOR_POINTER")
    print("CLAIM_BOUNDARY=route structural checker mechanism only; actual private source content is separately read back")


if __name__ == "__main__":
    main()
