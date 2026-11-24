"""Resilient stdlib HTTP client with retry, backoff, and transparent gzip decoding."""
from __future__ import annotations

import gzip
import random
import ssl
import time
import urllib.error
import urllib.request

DEFAULT_USER_AGENT = (
    "shougt-fips-fido-trust/1.0 (+https://github.com/whoiswei114514/shougt-fips-fido-trust)"
)


def _retry_after_seconds(headers) -> float | None:
    if not headers:
        return None
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        seconds = float(raw.strip())
    except ValueError:
        return None
    return max(0.5, min(seconds, 90.0))


def fetch_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 35,
    max_attempts: int = 4,
    base_delay: float = 2.0,
) -> bytes:
    """Fetch raw bytes from HTTP(S), transparently decoding gzip with backoff retries."""
    merged_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept-Encoding": "gzip",
    }
    if headers:
        merged_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(url, headers=merged_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                encoding = (resp.headers.get("Content-Encoding") or "").lower()
                if "gzip" in encoding or data[:2] == b"\x1f\x8b":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt == max_attempts:
                raise
            delay = _retry_after_seconds(exc.headers) or (base_delay * (2 ** (attempt - 1)))
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError, OSError) as exc:
            last_error = exc
            if attempt == max_attempts:
                raise
            delay = base_delay * (2 ** (attempt - 1))

        time.sleep(delay + random.uniform(0.0, 0.75))

    assert last_error is not None
    raise last_error


def fetch_text(url: str, *, headers: dict[str, str] | None = None, timeout: int = 35) -> str:
    """Fetch and decode UTF-8 text from an HTTP(S) URL."""
    return fetch_bytes(url, headers=headers, timeout=timeout).decode("utf-8", errors="replace")
