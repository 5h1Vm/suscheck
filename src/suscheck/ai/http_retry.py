"""HTTP helpers with basic 429 / rate-limit backoff (no extra dependencies)."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
MAX_BACKOFF_SEC = 90.0


def post_json_with_retry(
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any],
    timeout_sec: float,
    params: dict[str, str] | None = None,
) -> requests.Response:
    """POST JSON; on 429 / 503 retry with exponential backoff and optional Retry-After."""
    last: requests.Response | None = None
    for attempt in range(MAX_RETRIES):
        r = requests.post(
            url,
            params=params or {},
            json=json_body,
            headers=headers,
            timeout=timeout_sec,
        )
        last = r
        if r.status_code not in (429, 503):
            return r
        if attempt == MAX_RETRIES - 1:
            break
        ra = r.headers.get("Retry-After")
        if ra and ra.isdigit():
            wait = min(float(ra), MAX_BACKOFF_SEC)
        else:
            wait = min(2.0 ** attempt, MAX_BACKOFF_SEC)
        logger.warning(
            "AI HTTP %s (rate limit / unavailable); retry in %.1fs (attempt %s/%s)",
            r.status_code,
            wait,
            attempt + 1,
            MAX_RETRIES,
        )
        time.sleep(wait)
    assert last is not None
    return last
