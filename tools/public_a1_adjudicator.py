from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

EXPECTED_FIXTURE_COUNT = 65
EXPECTED_METAMORPHIC_COUNT = 30
MIRRORED_PATHS = (
    "tools/execution_hardening_kernel.py",
    "tools/material_predicate_acceptance.py",
    "tools/github_actions_visibility_self_test.py",
)


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="source_manifest.json")
    parser.add_argument("--raw-result", default="material_predicate_raw_result.json")
    parser.add_argument("--api-visibility", default="api_visibility_receipt.json")
    parser.add_argument("--output", default="a1_public_acceptance_receipt.json")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    raw_path = Path(args.raw_result)
    api_path = Path(args.api_visibility)
    manifest = read_json(manifest_path)
    raw = read_json(raw_path)
    api = read_json(api_path)
    failures: list[str] = []

    source_commit = str(manifest.get("source_commit_sha", ""))
    if manifest.get("schema_version") != "execution-hardening-public-source-manifest/v1":
        failures.append("MANIFEST_SCHEMA")
    if manifest.get("source_repository") != "chch13/-":
        failures.append("SOURCE_REPOSITORY")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        failures.append("SOURCE_COMMIT_FORMAT")
    if api.get("state") != "PASS":
        failures.append("API_VISIBILITY_NOT_PASS")
    if api.get("repository") != "chch13/execution-hardening-validator":
        failures.append("API_VISIBILITY_REPOSITORY_MISMATCH")
    if api.get("tested_commit_sha") != os.environ.get("GITHUB_SHA"):
        failures.append("API_VISIBILITY_VALIDATOR_COMMIT_MISMATCH")
    if raw.get("state") != "PASS":
        failures.append("RAW_ACCEPTANCE_NOT_PASS")

    exact_checks = {
        "expected_fixture_count": EXPECTED_FIXTURE_COUNT,
        "executed_fixture_count": EXPECTED_FIXTURE_COUNT,
        "passed_fixture_count": EXPECTED_FIXTURE_COUNT,
        "failed_fixture_count": 0,
        "expected_metamorphic_count": EXPECTED_METAMORPHIC_COUNT,
        "executed_metamorphic_count": EXPECTED_METAMORPHIC_COUNT,
        "passed_metamorphic_count": EXPECTED_METAMORPHIC_COUNT,
        "failed_metamorphic_count": 0,
        "unknown_result_count": 0,
    }
    for field, expected in exact_checks.items():
        if raw.get(field) != expected:
            failures.append(f"{field}:{raw.get(field)}!={expected}")

    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, dict):
        failures.append("MANIFEST_FILES")
        manifest_files = {}
    observed_blobs: dict[str, str] = {}
    source_blobs: dict[str, object] = {}
    for path in MIRRORED_PATHS:
        entry = manifest_files.get(path)
        expected_blob = entry.get("blob_sha") if isinstance(entry, dict) else None
        observed_blob = git_blob_sha(Path(path))
        observed_blobs[path] = observed_blob
        source_blobs[path] = expected_blob
        if not isinstance(expected_blob, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_blob):
            failures.append(f"SOURCE_BLOB_FORMAT:{path}")
        elif observed_blob != expected_blob:
            failures.append(f"SOURCE_BLOB_MISMATCH:{path}")

    receipt = {
        "schema_version": "execution-hardening-a1-public-acceptance-receipt/v1",
        "state": "PASS" if not failures else "FAIL",
        "source_repository": manifest.get("source_repository"),
        "source_commit_sha": source_commit,
        "source_blob_shas": source_blobs,
        "observed_mirror_blob_shas": observed_blobs,
        "validator_repository": "chch13/execution-hardening-validator",
        "validator_commit_sha": os.environ.get("GITHUB_SHA"),
        "validator_run_id": api.get("run_id"),
        "validator_run_attempt": api.get("run_attempt"),
        "executed_fixture_count": raw.get("executed_fixture_count"),
        "passed_fixture_count": raw.get("passed_fixture_count"),
        "failed_fixture_count": raw.get("failed_fixture_count"),
        "executed_metamorphic_count": raw.get("executed_metamorphic_count"),
        "passed_metamorphic_count": raw.get("passed_metamorphic_count"),
        "failed_metamorphic_count": raw.get("failed_metamorphic_count"),
        "unknown_result_count": raw.get("unknown_result_count"),
        "api_visibility_receipt_sha256": sha256_file(api_path),
        "raw_result_sha256": sha256_file(raw_path),
        "source_manifest_sha256": sha256_file(manifest_path),
        "trust_model": "PUBLIC_GITHUB_HOSTED_VALIDATOR_PLUS_CONTENT_ADDRESSED_PRIVATE_SOURCE_IDENTITY",
        "failures": failures,
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
    Path(args.output).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    if receipt["state"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
