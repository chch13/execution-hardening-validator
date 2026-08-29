from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "execution-hardening-raw-tree-evidence/v1"
SCANNER_VERSION = "execution-hardening-raw-tree-scanner/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
TEXT_SUFFIXES = frozenset({".py", ".ps1", ".sh", ".yml", ".yaml", ".json", ".md", ".txt", ".toml"})
WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})

OBSERVATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WORKFLOW_ON_KEY", re.compile(r"(?m)^\s*on\s*:")),
    ("WORKFLOW_RUNS_ON_KEY", re.compile(r"(?m)^\s*runs-on\s*:")),
    ("WORKFLOW_NEEDS_KEY", re.compile(r"(?m)^\s*needs\s*:")),
    ("WORKFLOW_USES_KEY", re.compile(r"(?m)^\s*-?\s*uses\s*:")),
    ("WORKFLOW_RUN_KEY", re.compile(r"(?m)^\s*-?\s*run\s*:")),
    ("WORKFLOW_DISPATCH_TEXT", re.compile(r"\bworkflow_dispatch\b")),
    ("REPOSITORY_DISPATCH_TEXT", re.compile(r"\brepository_dispatch\b")),
    ("SUBPROCESS_TEXT", re.compile(r"\bsubprocess\b")),
    ("OS_SYSTEM_TEXT", re.compile(r"\bos\.system\b")),
    ("POWERSHELL_START_PROCESS_TEXT", re.compile(r"\bStart-Process\b", re.IGNORECASE)),
    ("REQUESTS_TEXT", re.compile(r"\brequests\b")),
    ("HTTP_CLIENT_TEXT", re.compile(r"\b(?:urllib|http\.client|Invoke-RestMethod|Invoke-WebRequest)\b", re.IGNORECASE)),
    ("OPERATION_ID_TEXT", re.compile(r"\boperation[_-]?id\b", re.IGNORECASE)),
    ("RUNNER_TEXT", re.compile(r"\brunner\b", re.IGNORECASE)),
    ("TARGET_TEXT", re.compile(r"\btarget\b", re.IGNORECASE)),
    ("RESOURCE_TEXT", re.compile(r"\bresource\b", re.IGNORECASE)),
    ("DISPATCH_TEXT", re.compile(r"\bdispatch\b", re.IGNORECASE)),
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _run_git(repo: Path, *args: str, binary: bool = False) -> bytes | str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
    return proc.stdout if binary else proc.stdout.decode("utf-8", errors="strict")


def resolve_exact_commit(repo: Path, requested: str) -> str:
    if not isinstance(requested, str) or not requested.strip():
        raise ValueError("tested_commit_sha is required")
    resolved = str(_run_git(repo, "rev-parse", "--verify", f"{requested.strip()}^{{commit}}" )).strip().lower()
    if not HEX40.fullmatch(resolved):
        raise RuntimeError("resolved commit is not a 40-char SHA1")
    if requested.strip().lower() != resolved:
        raise ValueError("tested_commit_sha must be the exact 40-char commit SHA, not a branch/tag/abbreviation")
    return resolved


def _parse_ls_tree(raw: bytes) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path_bytes = record.split(b"\t", 1)
        mode, object_type, object_sha = meta.decode("ascii").split(" ", 2)
        path = path_bytes.decode("utf-8", errors="surrogateescape")
        entries.append({"mode": mode, "object_type": object_type, "object_sha": object_sha, "path": path})
    entries.sort(key=lambda item: item["path"])
    return entries


def _is_text_candidate(path: str) -> bool:
    p = Path(path)
    return p.suffix.lower() in TEXT_SUFFIXES


def _read_blob(repo: Path, object_sha: str) -> bytes:
    data = _run_git(repo, "cat-file", "blob", object_sha, binary=True)
    assert isinstance(data, bytes)
    return data


def _blob_size(repo: Path, object_sha: str) -> int:
    out = str(_run_git(repo, "cat-file", "-s", object_sha)).strip()
    return int(out)


def _observe_text(path: str, raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "text_decode": "UTF8",
        "observations": [],
    }
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["text_decode"] = "NON_UTF8_OR_BINARY"
        return result

    observations: list[dict[str, Any]] = []
    for observation_type, pattern in OBSERVATION_PATTERNS:
        matches = list(pattern.finditer(text))
        if not matches:
            continue
        lines = sorted({text.count("\n", 0, match.start()) + 1 for match in matches})
        observations.append({
            "type": observation_type,
            "count": len(matches),
            "line_numbers": lines,
        })
    if path.startswith(".github/workflows/") and Path(path).suffix.lower() in WORKFLOW_SUFFIXES:
        observations.append({"type": "WORKFLOW_PATH", "count": 1, "line_numbers": []})
    observations.sort(key=lambda item: item["type"])
    result["observations"] = observations
    return result


def scan_repository(repo_root: str | os.PathLike[str], tested_commit_sha: str) -> dict[str, Any]:
    repo = Path(repo_root).resolve()
    if not (repo / ".git").exists():
        raise ValueError("repo_root must be a git working tree root with .git present")
    resolved = resolve_exact_commit(repo, tested_commit_sha)
    raw_tree = _run_git(repo, "ls-tree", "-r", "-z", "--full-tree", resolved, binary=True)
    assert isinstance(raw_tree, bytes)
    entries = _parse_ls_tree(raw_tree)

    files: list[dict[str, Any]] = []
    observation_count = 0
    observed_file_count = 0
    for entry in entries:
        if entry["object_type"] != "blob":
            continue
        record: dict[str, Any] = {
            **entry,
            "size_bytes": _blob_size(repo, entry["object_sha"]),
            "text_candidate": _is_text_candidate(entry["path"]),
        }
        if record["text_candidate"]:
            raw = _read_blob(repo, entry["object_sha"])
            lexical = _observe_text(entry["path"], raw)
            record.update(lexical)
            if lexical["observations"]:
                observed_file_count += 1
                observation_count += sum(int(x["count"]) for x in lexical["observations"])
        files.append(record)

    no_hash = {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "tested_commit_sha": resolved,
        "tree_entry_count": len(entries),
        "blob_count": len(files),
        "observed_file_count": observed_file_count,
        "lexical_observation_count": observation_count,
        "classification_claim": "NONE_RAW_EVIDENCE_ONLY",
        "files": files,
    }
    return {**no_hash, "artifact_sha256": sha256_hex(no_hash)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--tested-commit-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = scan_repository(args.repo, args.tested_commit_sha)
    output = Path(args.output)
    output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("EXECUTION_HARDENING_RAW_TREE_SCAN_PASS")
    print(f"TESTED_COMMIT_SHA={result['tested_commit_sha']}")
    print(f"TREE_ENTRY_COUNT={result['tree_entry_count']}")
    print(f"BLOB_COUNT={result['blob_count']}")
    print(f"OBSERVED_FILE_COUNT={result['observed_file_count']}")
    print(f"LEXICAL_OBSERVATION_COUNT={result['lexical_observation_count']}")
    print(f"ARTIFACT_SHA256={result['artifact_sha256']}")
    print("CLASSIFICATION_CLAIM=NONE_RAW_EVIDENCE_ONLY")


if __name__ == "__main__":
    main()
