"""Tests for the NVD HTTP client with Requests fully stubbed."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


def make_response(payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload or {"vulnerabilities": []}
    return response


def test_fetch_uses_single_expected_request(monkeypatch):
    response = make_response()
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    assert api_client.fetch_response(CVE_ID) == {"vulnerabilities": []}
    fake_get.assert_called_once_with(
        api_client.API_URL,
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


@pytest.mark.parametrize(
    "raw_key, expected",
    [(None, None), ("", None), ("  \t ", None), ("  fake-key  ", "fake-key")],
)
def test_build_headers_handles_optional_key(monkeypatch, raw_key, expected):
    if raw_key is None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    else:
        monkeypatch.setenv("NVD_API_KEY", raw_key)
    headers = api_client.build_headers()
    assert headers["Accept"] == "application/json"
    assert headers.get("apiKey") == expected


def test_fetch_sends_trimmed_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", " fake-key ")
    fake_get = Mock(return_value=make_response())
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    api_client.fetch_response(CVE_ID)
    assert fake_get.call_args.kwargs["headers"] == {
        "Accept": "application/json",
        "apiKey": "fake-key",
    }


def test_connection_error_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(side_effect=requests.exceptions.Timeout("sensitive details")),
    )
    with pytest.raises(api_client.APIClientError, match="очікування") as error:
        api_client.fetch_response(CVE_ID)
    assert "sensitive details" not in str(error.value)


def test_http_error_reports_status_without_body(monkeypatch):
    response = make_response()
    response.status_code = 503
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=response
    )
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match="503"):
        api_client.fetch_response(CVE_ID)


def test_unexpected_non_error_status_is_rejected(monkeypatch):
    response = make_response()
    response.status_code = 204
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match="204"):
        api_client.fetch_response(CVE_ID)


def test_invalid_json_is_rejected(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError("invalid", "{", 1)
    monkeypatch.setattr(api_client.requests, "get", Mock(return_value=response))
    with pytest.raises(api_client.APIClientError, match="JSON"):
        api_client.fetch_response(CVE_ID)
