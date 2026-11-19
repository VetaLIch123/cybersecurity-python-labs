"""Small, defensive client for the NVD CVE API 2.0."""

from __future__ import annotations

import os
from typing import Any

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class APIClientError(Exception):
    """An API failure with a message safe to show without exposing secrets."""


def build_headers() -> dict[str, str]:
    """Build NVD request headers, reading an optional API key at call time."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Fetch one CVE result, with bounded timeouts and sanitized failures."""
    try:
        response = requests.get(
            API_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=(3.05, 10),
            allow_redirects=False,
        )
    except requests.exceptions.Timeout as exc:
        raise APIClientError("Час очікування відповіді NVD вичерпано.") from exc
    except requests.exceptions.RequestException as exc:
        raise APIClientError("Не вдалося з'єднатися з NVD API.") from exc

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        status = response.status_code
        raise APIClientError(f"NVD API повернув HTTP-помилку {status}.") from exc

    if response.status_code != 200:
        raise APIClientError(
            f"NVD API повернув неочікуваний статус HTTP {response.status_code}."
        )

    try:
        return response.json()
    except (requests.exceptions.JSONDecodeError, ValueError) as exc:
        raise APIClientError("NVD API повернув некоректний JSON.") from exc
