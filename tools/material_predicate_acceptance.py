from __future__ import annotations

import argparse
import json
from pathlib import Path

from execution_hardening_kernel import (
    ExecutionNode,
    MaterialClassification,
    classify_material_graph,
    execution_graph_digest,
)

VARIANTS = 5
FIXTURE_CASES = 13
METAMORPHIC_CASES = 6
EXPECTED_FIXTURE_COUNT = FIXTURE_CASES * VARIANTS
EXPECTED_METAMORPHIC_COUNT = METAMORPHIC_CASES * VARIANTS


def node(node_id: str, *, primitives=(), children=(), proof=False, generic=False, unresolved=False) -> ExecutionNode:
    return ExecutionNode(
        node_id=node_id,
        primitives=tuple(primitives),
        children=tuple(children),
        read_only_proof=proof,
        generic_exec=generic,
        unresolved_external=unresolved,
    )


def expect(graph: dict[str, ExecutionNode], entry: str, expected: MaterialClassification) -> None:
    actual = classify_material_graph(graph, entry).classification
    if actual is not expected:
        raise AssertionError(f"{entry}: expected {expected.value}, got {actual.value}")


def k01(v: int) -> None:
    expect({"e": node("e", primitives=[f"fs_write:{v}"])}, "e", MaterialClassification.MATERIAL)


def k02(v: int) -> None:
    expect({"e": node("e", primitives=[f"process_start:{v}"])}, "e", MaterialClassification.MATERIAL)


def k03(v: int) -> None:
    expect({"e": node("e", primitives=[f"dom_insert:{v}"])}, "e", MaterialClassification.MATERIAL)


def k04(v: int) -> None:
    expect({"e": node("e", primitives=[f"repo_write:{v}"])}, "e", MaterialClassification.MATERIAL)


def k05(v: int) -> None:
    graph = {
        "wrapper": node("wrapper", children=["child"], proof=True),
        "child": node("child", primitives=[f"fs_delete:{v}"]),
    }
    expect(graph, "wrapper", MaterialClassification.TRANSITIVE_MATERIAL)


def k06(v: int) -> None:
    expect({"e": node("e", primitives=[f"shell:{v}"], generic=True)}, "e", MaterialClassification.UNKNOWN)


def k07(v: int) -> None:
    graph = {
        "e": node("e", primitives=[f"fs_read:{v}"], children=["c"], proof=True),
        "c": node("c", primitives=[f"hash:{v}"], proof=True),
    }
    expect(graph, "e", MaterialClassification.READ_ONLY_NON_MATERIAL)


def k08(v: int) -> None:
    expect({"e": node("e", children=[f"missing-{v}"], proof=True)}, "e", MaterialClassification.UNKNOWN)


def k09(v: int) -> None:
    # Classification is based on the graph, not filename/comment semantics.
    expect({"looks_read_only_but_isnt": node("looks_read_only_but_isnt", primitives=[f"current_update:{v}"])}, "looks_read_only_but_isnt", MaterialClassification.MATERIAL)


def k10(v: int) -> None:
    graph = {
        "alias": node("alias", children=["mutator"], proof=True),
        "mutator": node("mutator", primitives=[f"service_mutation:{v}"]),
    }
    expect(graph, "alias", MaterialClassification.TRANSITIVE_MATERIAL)


def k11(v: int) -> None:
    graph = {
        "a": node("a", children=["b"], proof=True),
        "b": node("b", children=["a", "m"], proof=True),
        "m": node("m", primitives=[f"ui_input:{v}"]),
    }
    expect(graph, "a", MaterialClassification.TRANSITIVE_MATERIAL)


def k12(v: int) -> None:
    graph = {
        "a": node("a", children=["b"], proof=True),
        "b": node("b", children=["a"], proof=False),
    }
    expect(graph, "a", MaterialClassification.UNKNOWN)


def k13(v: int) -> None:
    expect({"e": node("e", unresolved=True)}, "e", MaterialClassification.UNKNOWN)


FIXTURES = [k01, k02, k03, k04, k05, k06, k07, k08, k09, k10, k11, k12, k13]


def p01(v: int) -> None:
    base = {"e": node("e", primitives=[f"fs_write:{v}"])}
    mutated = {"e": node("e", primitives=[f"fs_write:{v}", f"fs_read:{v}"], proof=True)}
    if classify_material_graph(base, "e").classification is not MaterialClassification.MATERIAL:
        raise AssertionError("base not material")
    if classify_material_graph(mutated, "e").classification is MaterialClassification.READ_ONLY_NON_MATERIAL:
        raise AssertionError("material edge downgraded to read-only")


def p02(v: int) -> None:
    graph = {"e": node("e", primitives=[f"fs_read:{v}"], children=["missing"], proof=True)}
    if classify_material_graph(graph, "e").classification is MaterialClassification.READ_ONLY_NON_MATERIAL:
        raise AssertionError("unresolved edge became read-only")


def p03(v: int) -> None:
    proven = {"e": node("e", primitives=[f"fs_read:{v}"], proof=True)}
    unproven = {"e": node("e", primitives=[f"fs_read:{v}"], proof=False)}
    if classify_material_graph(proven, "e").classification is not MaterialClassification.READ_ONLY_NON_MATERIAL:
        raise AssertionError("proven graph not read-only")
    if classify_material_graph(unproven, "e").classification is MaterialClassification.READ_ONLY_NON_MATERIAL:
        raise AssertionError("proof deletion upgraded unknown to read-only")


def p04(v: int) -> None:
    a = {"safe-name": node("safe-name", primitives=[f"repo_write:{v}"])}
    b = {"danger-name": node("danger-name", primitives=[f"repo_write:{v}"])}
    if classify_material_graph(a, "safe-name").classification is not classify_material_graph(b, "danger-name").classification:
        raise AssertionError("node naming changed classification")


def p05(v: int) -> None:
    a = {
        "e": node("e", children=["c"], proof=True),
        "c": node("c", primitives=[f"fs_read:{v}"], proof=True),
    }
    b = {
        "c": node("c", primitives=[f"fs_read:{v}"], proof=True),
        "e": node("e", children=["c"], proof=True),
    }
    da = classify_material_graph(a, "e")
    db = classify_material_graph(b, "e")
    if da.classification is not db.classification or execution_graph_digest(a) != execution_graph_digest(b):
        raise AssertionError("normalized graph result/digest drifted")


def p06(v: int) -> None:
    graph = {
        "parent": node("parent", children=["child"], proof=True),
        "child": node("child", primitives=[f"runtime_state_write:{v}"]),
    }
    if classify_material_graph(graph, "parent").classification is MaterialClassification.READ_ONLY_NON_MATERIAL:
        raise AssertionError("material child permitted read-only parent")


METAMORPHIC = [p01, p02, p03, p04, p05, p06]


def run() -> dict[str, object]:
    fixture_failures: list[str] = []
    metamorphic_failures: list[str] = []
    fixture_count = 0
    metamorphic_count = 0

    for case_index, test in enumerate(FIXTURES, start=1):
        for variant in range(1, VARIANTS + 1):
            fixture_count += 1
            try:
                test(variant)
            except Exception as exc:
                fixture_failures.append(f"K{case_index:02d}[{variant}]: {exc}")

    for case_index, test in enumerate(METAMORPHIC, start=1):
        for variant in range(1, VARIANTS + 1):
            metamorphic_count += 1
            try:
                test(variant)
            except Exception as exc:
                metamorphic_failures.append(f"P{case_index}[{variant}]: {exc}")

    failures = fixture_failures + metamorphic_failures
    return {
        "schema_version": "material-predicate-raw-result/v1",
        "fixture_cases": FIXTURE_CASES,
        "variants": VARIANTS,
        "expected_fixture_count": EXPECTED_FIXTURE_COUNT,
        "executed_fixture_count": fixture_count,
        "passed_fixture_count": fixture_count - len(fixture_failures),
        "failed_fixture_count": len(fixture_failures),
        "metamorphic_cases": METAMORPHIC_CASES,
        "expected_metamorphic_count": EXPECTED_METAMORPHIC_COUNT,
        "executed_metamorphic_count": metamorphic_count,
        "passed_metamorphic_count": metamorphic_count - len(metamorphic_failures),
        "failed_metamorphic_count": len(metamorphic_failures),
        "unknown_result_count": 0,
        "failures": failures,
        "state": "PASS" if not failures else "FAIL",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="material_predicate_raw_result.json")
    args = parser.parse_args()
    result = run()
    Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if result["state"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
