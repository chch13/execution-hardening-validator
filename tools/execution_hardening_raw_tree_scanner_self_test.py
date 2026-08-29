from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from execution_hardening_raw_tree_scanner import scan_repository


def run(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout.strip()


def write(repo: Path, rel: str, data: bytes) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def expect_exception(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        return
    raise AssertionError(f"expected exception: {label}")


def main() -> None:
    tests = 0
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        run(repo, "init", "-q")
        run(repo, "config", "user.email", "scanner-selftest@example.invalid")
        run(repo, "config", "user.name", "scanner-selftest")
        write(repo, ".github/workflows/sample.yml", b"name: sample\non:\n  workflow_dispatch:\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python tools/a.py\n")
        write(repo, "tools/a.py", b"import subprocess\noperation_id = 'abc'\ntarget = 'T'\n")
        write(repo, "notes.txt", b"plain evidence\n")
        write(repo, "opaque.txt", b"\xff\xfe\x00\x01")
        run(repo, "add", ".")
        run(repo, "commit", "-q", "-m", "fixture one")
        c1 = run(repo, "rev-parse", "HEAD")

        first = scan_repository(repo, c1)
        second = scan_repository(repo, c1)
        if first != second:
            raise AssertionError("same commit scan is nondeterministic")
        tests += 1
        if first["tested_commit_sha"] != c1 or first["classification_claim"] != "NONE_RAW_EVIDENCE_ONLY":
            raise AssertionError("exact commit/claim boundary drifted")
        tests += 1

        by_path = {item["path"]: item for item in first["files"]}
        wf_types = {item["type"] for item in by_path[".github/workflows/sample.yml"]["observations"]}
        required = {"WORKFLOW_PATH", "WORKFLOW_ON_KEY", "WORKFLOW_RUNS_ON_KEY", "WORKFLOW_RUN_KEY", "WORKFLOW_DISPATCH_TEXT"}
        if not required.issubset(wf_types):
            raise AssertionError(f"workflow lexical evidence missing: {sorted(required - wf_types)}")
        tests += 1
        py_types = {item["type"] for item in by_path["tools/a.py"]["observations"]}
        if not {"SUBPROCESS_TEXT", "OPERATION_ID_TEXT", "TARGET_TEXT"}.issubset(py_types):
            raise AssertionError("script lexical evidence missing")
        tests += 1
        if by_path["opaque.txt"].get("text_decode") != "NON_UTF8_OR_BINARY":
            raise AssertionError("non-UTF8 evidence was silently decoded")
        tests += 1

        write(repo, ".github/workflows/sample.yml", b"name: changed\non:\n  repository_dispatch:\n")
        run(repo, "add", ".")
        run(repo, "commit", "-q", "-m", "fixture two")
        c2 = run(repo, "rev-parse", "HEAD")
        old_again = scan_repository(repo, c1)
        new_scan = scan_repository(repo, c2)
        if old_again != first or old_again["artifact_sha256"] == new_scan["artifact_sha256"]:
            raise AssertionError("scanner followed working tree/HEAD instead of tested commit")
        tests += 1

        expect_exception(lambda: scan_repository(repo, "HEAD"), "symbolic ref must fail")
        expect_exception(lambda: scan_repository(repo, c1[:12]), "abbreviated sha must fail")
        tests += 1

    print("EXECUTION_HARDENING_RAW_TREE_SCANNER_SELF_TEST_PASS")
    print(f"TOTAL_TESTS={tests}")
    print("CRITICAL_ERRORS=0")
    print("CLAIM_BOUNDARY=scanner mechanism only; no final B0 schema/classification/content completeness claim")


if __name__ == "__main__":
    main()
