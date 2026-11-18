"""A small GitHub API client for creating check runs (standard library only)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote


class GitHubClient:
    def __init__(self, token: str, api_url: str = "https://api.github.com", timeout: int = 30):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any]]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=body,
            method=method,
            headers={
                "authorization": f"Bearer {self.token}",
                "accept": "application/vnd.github+json",
                "content-type": "application/json",
                "x-github-api-version": "2022-11-28",
                "user-agent": "osv-pulse-runner",
            },
        )

        last_error: tuple[int, dict[str, Any]] | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    text = response.read().decode("utf-8")
                    return response.status, json.loads(text) if text else {}
            except urllib.error.HTTPError as exc:
                text = exc.read().decode("utf-8", errors="replace")
                error: dict[str, Any] = {"message": text[:1000]}
                if 500 <= exc.code < 600 and attempt < 2:
                    last_error = (exc.code, error)
                    time.sleep(2**attempt)
                    continue
                return exc.code, error
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = (0, {"message": str(exc)})
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                break
        return last_error or (0, {"message": "unknown network error"})

    def create_check_run(
        self, owner: str, repo: str, body: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        path = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/check-runs"
        return self.request("POST", path, body)
