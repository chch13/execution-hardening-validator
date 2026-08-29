from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
MAX_RETRIES = 3


class VisibilityBlocked(RuntimeError):
    pass


class VisibilityFailed(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_link_next(link: str | None) -> str | None:
    if not link:
        return None
    for item in link.split(","):
        pieces = [x.strip() for x in item.split(";")]
        if len(pieces) < 2:
            continue
        url = pieces[0]
        rels = pieces[1:]
        if any('rel="next"' == rel for rel in rels):
            return url.strip("<>")
    return None


def request_json(url: str, token: str, stats: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "execution-hardening-visibility-self-test",
    }
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                body = response.read()
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                stats["request_count"] += 1
                stats["retry_count"] += attempt
                remaining = response_headers.get("x-ratelimit-remaining")
                if remaining == "0":
                    raise VisibilityBlocked("RATE_LIMIT_REMAINING_ZERO")
                return json.loads(body.decode("utf-8")), response_headers
        except urllib.error.HTTPError as exc:
            stats["request_count"] += 1
            status = exc.code
            response_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            if status in (401, 403, 404):
                if status == 403 and (response_headers.get("x-ratelimit-remaining") == "0" or "retry-after" in response_headers):
                    raise VisibilityBlocked(f"HTTP_{status}_RATE_LIMIT") from exc
                raise VisibilityFailed(f"HTTP_{status}_VISIBILITY_OR_AUTHORITY_NOT_PROVEN") from exc
            if status == 429 or 500 <= status <= 599:
                last_error = exc
                if attempt < MAX_RETRIES:
                    time.sleep(min(2 ** attempt, 4))
                    continue
                raise VisibilityBlocked(f"TRANSIENT_HTTP_{status}_RETRIES_EXHAUSTED") from exc
            raise VisibilityFailed(f"HTTP_{status}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 4))
                continue
            raise VisibilityBlocked("NETWORK_RETRIES_EXHAUSTED") from exc
    raise VisibilityBlocked(f"UNREACHABLE:{last_error}")


def paginated_jobs(url: str, token: str, stats: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    jobs: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    total_count: int | None = None
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > 1000:
            raise VisibilityFailed("PAGINATION_LOOP_OR_EXCESS")
        payload, headers = request_json(next_url, token, stats)
        page_total = payload.get("total_count")
        if not isinstance(page_total, int):
            raise VisibilityFailed("MISSING_TOTAL_COUNT")
        if total_count is None:
            total_count = page_total
        elif total_count != page_total:
            raise VisibilityFailed("TOTAL_COUNT_DRIFT_DURING_PAGINATION")
        page_jobs = payload.get("jobs")
        if not isinstance(page_jobs, list):
            raise VisibilityFailed("MISSING_JOBS_ARRAY")
        for job in page_jobs:
            job_id = job.get("id")
            if not isinstance(job_id, int):
                raise VisibilityFailed("JOB_ID_MISSING")
            if job_id in seen_ids:
                raise VisibilityFailed("DUPLICATE_JOB_ID")
            seen_ids.add(job_id)
            jobs.append(job)
        next_url = parse_link_next(headers.get("link"))
    if total_count is None:
        raise VisibilityFailed("NO_PAGINATION_RESPONSE")
    if len(seen_ids) != total_count:
        raise VisibilityFailed(f"PAGINATION_INCOMPLETE:{len(seen_ids)}!={total_count}")
    return jobs, total_count


def canonical_job_identity(job: dict[str, Any]) -> tuple[int, str, int]:
    return (int(job["id"]), str(job.get("name", "")), int(job.get("run_attempt", 0) or 0))


def run_self_test() -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt_env = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    tested_commit = os.environ.get("GITHUB_SHA", "")
    token = os.environ.get("GH_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
    if not all([repository, run_id, run_attempt_env, tested_commit, token]):
        raise VisibilityFailed("REQUIRED_GITHUB_ENV_MISSING")
    run_attempt = int(run_attempt_env)
    stats: dict[str, Any] = {"request_count": 0, "retry_count": 0}

    run_url = f"{API_ROOT}/repos/{repository}/actions/runs/{run_id}"
    run, _ = request_json(run_url, token, stats)
    if str(run.get("id")) != run_id:
        raise VisibilityFailed("RUN_ID_MISMATCH")
    if run.get("head_sha") != tested_commit:
        raise VisibilityFailed("HEAD_SHA_MISMATCH")
    if int(run.get("run_attempt", 0)) != run_attempt:
        raise VisibilityFailed("RUN_ATTEMPT_MISMATCH")

    runwide_url = f"{run_url}/jobs?filter=all&per_page=100"
    runwide_jobs, runwide_total = paginated_jobs(runwide_url, token, stats)

    canaries = [j for j in runwide_jobs if j.get("name") == "api-visibility-canary"]
    if len(canaries) != 1:
        raise VisibilityFailed(f"CANARY_COUNT:{len(canaries)}")
    canary = canaries[0]
    if canary.get("conclusion") != "success":
        raise VisibilityFailed(f"CANARY_NOT_SUCCESS:{canary.get('conclusion')}")
    if canary.get("head_sha") not in (None, tested_commit):
        raise VisibilityFailed("CANARY_HEAD_SHA_MISMATCH")

    attempt_jobs: list[dict[str, Any]] = []
    attempt_totals: dict[str, int] = {}
    for attempt in range(1, run_attempt + 1):
        attempt_url = f"{run_url}/attempts/{attempt}/jobs?per_page=100"
        jobs, total = paginated_jobs(attempt_url, token, stats)
        attempt_jobs.extend(jobs)
        attempt_totals[str(attempt)] = total

    runwide_ids = {int(j["id"]) for j in runwide_jobs}
    attempt_ids = {int(j["id"]) for j in attempt_jobs}
    if runwide_ids != attempt_ids:
        raise VisibilityFailed("RUNWIDE_ATTEMPT_UNIVERSE_MISMATCH")

    runwide_identity = sorted(canonical_job_identity(j) for j in runwide_jobs)
    attempt_identity = sorted(canonical_job_identity(j) for j in attempt_jobs)
    runwide_hash = sha256_bytes(json.dumps(runwide_identity, separators=(",", ":")).encode())
    attempt_hash = sha256_bytes(json.dumps(attempt_identity, separators=(",", ":")).encode())

    return {
        "schema_version": "github-actions-api-visibility-receipt/v1",
        "state": "PASS",
        "repository": repository,
        "tested_commit_sha": tested_commit,
        "run_id": int(run_id),
        "run_attempt": run_attempt,
        "permissions_declared": ["actions:read", "contents:read"],
        "api_version": "2022-11-28",
        "canary_job_identity": canonical_job_identity(canary),
        "canary_seen_count": 1,
        "runwide_total_count": runwide_total,
        "runwide_collected_unique_count": len(runwide_ids),
        "attempt_numbers_checked": list(range(1, run_attempt + 1)),
        "attempt_total_counts": attempt_totals,
        "attempt_collected_unique_count": len(attempt_ids),
        "runwide_job_universe_hash": runwide_hash,
        "attempt_union_job_universe_hash": attempt_hash,
        "pagination_complete": True,
        "rate_limit_observation": "NO_BLOCK_OBSERVED",
        "http_error_count": 0,
        "request_count": stats["request_count"],
        "retry_count": stats["retry_count"],
        "trust_model": "PLATFORM_TRUST_ASSUMPTION_GITHUB_CONTROL_PLANE",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="api_visibility_receipt.json")
    args = parser.parse_args()
    try:
        result = run_self_test()
    except VisibilityBlocked as exc:
        result = {
            "schema_version": "github-actions-api-visibility-receipt/v1",
            "state": "BLOCKED",
            "reason": str(exc),
            "trust_model": "PLATFORM_TRUST_ASSUMPTION_GITHUB_CONTROL_PLANE",
        }
    except Exception as exc:
        result = {
            "schema_version": "github-actions-api-visibility-receipt/v1",
            "state": "FAIL",
            "reason": str(exc),
            "trust_model": "PLATFORM_TRUST_ASSUMPTION_GITHUB_CONTROL_PLANE",
        }
    encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    result["receipt_sha256"] = sha256_bytes(encoded)
    Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    if result["state"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
