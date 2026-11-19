"""CLI tests for local input, argument validation, and error reporting."""

import json
from pathlib import Path

import pytest

from labs.lab04 import main as cli

CVE_ID = "CVE-2099-10001"
SAMPLE = Path(__file__).parents[1] / "data" / "nvd_sample.json"


def test_local_mode_prints_one_json_report_without_network(monkeypatch, capsys):
    def no_network(_cve_id):
        raise AssertionError("local mode must not call the API")

    monkeypatch.setattr(cli.api_client, "fetch_response", no_network)
    assert cli.main(["--cve", CVE_ID, "--input", str(SAMPLE)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["decision"] == "review"
    assert report["rule"] == {
        "threshold": 8.0,
        "field": "userInteraction",
        "expected": "NONE",
    }
    assert captured.out.count("\n") == 1


def test_invalid_cve_is_argparse_error(capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--cve", "cve-2021-1234", "--input", str(SAMPLE)])
    assert error.value.code == 2
    assert "CVE" in capsys.readouterr().err


def test_missing_input_file_returns_code_one(capsys, tmp_path):
    result = cli.main(["--cve", CVE_ID, "--input", str(tmp_path / "missing.json")])
    assert result == 1
    assert "Помилка читання файла" in capsys.readouterr().err


def test_invalid_json_returns_code_one(capsys, tmp_path):
    invalid = tmp_path / "bad.json"
    invalid.write_text("{", encoding="utf-8")
    result = cli.main(["--cve", CVE_ID, "--input", str(invalid)])
    assert result == 1
    assert "некоректний JSON" in capsys.readouterr().err


def test_bad_payload_returns_code_one(capsys, tmp_path):
    bad = tmp_path / "bad-structure.json"
    bad.write_text(json.dumps({"vulnerabilities": None}), encoding="utf-8")
    result = cli.main(["--cve", CVE_ID, "--input", str(bad)])
    assert result == 1
    assert "Помилка даних" in capsys.readouterr().err


def test_invalid_variant_returns_code_two_before_loading(monkeypatch, capsys):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", True)
    monkeypatch.setattr(
        cli, "load_response", lambda _path: pytest.fail("must validate variant first")
    )
    result = cli.main(["--cve", CVE_ID, "--input", "ignored.json"])
    assert result == 2
    assert "VARIANT_NUMBER" in capsys.readouterr().err


def test_online_mode_uses_client_and_prints_report(monkeypatch, capsys):
    monkeypatch.setattr(
        cli.api_client,
        "fetch_response",
        lambda _cve_id: json.loads(SAMPLE.read_text(encoding="utf-8")),
    )
    assert cli.main(["--cve", CVE_ID]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "review"
