"""Tests for NVD response validation and variant rule evaluation."""

import copy
import json
import math
from pathlib import Path

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
SAMPLE = Path(__file__).parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def payload():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def report_for(payload, variant=4):
    return build_report(extract_record(payload, CVE_ID), CVE_ID, variant)


@pytest.mark.parametrize(
    ("score", "expected"),
    [(7.9, "other"), (8.0, "review"), (8.1, "review")],
)
def test_variant_four_score_boundary(payload, score, expected):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = score
    assert report_for(payload)["decision"] == expected


def test_high_score_with_wrong_interaction_is_other(payload):
    data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    data["baseScore"] = 10.0
    data["userInteraction"] = "REQUIRED"
    assert report_for(payload)["decision"] == "other"


def test_sample_report_contains_variant_four_rule(payload):
    report = report_for(payload)
    assert report["rule"] == {
        "threshold": 8.0,
        "field": "userInteraction",
        "expected": "NONE",
    }
    assert report["observed"] == "NONE"
    assert report["decision"] == "review"


def test_not_found_report_has_null_data():
    report = build_report(None, CVE_ID, 4)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == 4
    assert report["rule"]["field"] == "userInteraction"
    assert all(
        report[key] is None
        for key in ("description", "vuln_status", "score", "observed")
    )


def test_rejected_short_circuits_even_malformed_metrics(payload):
    cve = payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = None
    report = report_for(payload)
    assert report["decision"] == "rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None


def test_missing_status_short_circuits_score_analysis(payload):
    cve = payload["vulnerabilities"][0]["cve"]
    del cve["vulnStatus"]
    cve["metrics"] = None
    assert report_for(payload)["decision"] == "insufficient_data"


@pytest.mark.parametrize(
    "cve_update", [{}, {"metrics": {}}, {"metrics": {"cvssMetricV31": []}}]
)
def test_absent_score_is_insufficient_data(payload, cve_update):
    cve = payload["vulnerabilities"][0]["cve"]
    if cve_update:
        cve.update(cve_update)
    else:
        cve.pop("metrics")
    assert report_for(payload)["decision"] == "insufficient_data"


def test_absent_variant_field_is_insufficient_data(payload):
    data = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
        "cvssData"
    ]
    del data["userInteraction"]
    assert report_for(payload)["decision"] == "insufficient_data"


def test_first_primary_metric_is_selected_over_previous_secondary(payload):
    cve = payload["vulnerabilities"][0]["cve"]
    metrics = cve["metrics"]["cvssMetricV31"]
    secondary = copy.deepcopy(metrics[0])
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 4.0
    secondary["cvssData"]["userInteraction"] = "REQUIRED"
    metrics.insert(0, secondary)
    assert report_for(payload)["decision"] == "review"
    assert report_for(payload)["score"] == 9.8


def test_first_metric_is_fallback_when_no_primary(payload):
    cve = payload["vulnerabilities"][0]["cve"]
    metrics = cve["metrics"]["cvssMetricV31"]
    metrics[0]["type"] = "Secondary"
    fallback = copy.deepcopy(metrics[0])
    fallback["cvssData"]["baseScore"] = 5.0
    metrics.append(fallback)
    assert report_for(payload)["score"] == 9.8


@pytest.mark.parametrize("score", [True, "9.8", -0.1, 10.1, math.inf, math.nan])
def test_invalid_score_raises_value_error(payload, score):
    payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = score
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda cve: cve.update(vulnStatus=None),
        lambda cve: cve.update(descriptions=None),
        lambda cve: cve["metrics"].update(cvssMetricV31=None),
        lambda cve: cve["metrics"]["cvssMetricV31"][0].update(cvssData=None),
        lambda cve: cve["metrics"]["cvssMetricV31"][0]["cvssData"].update(
            version="4.0"
        ),
        lambda cve: cve["metrics"]["cvssMetricV31"][0]["cvssData"].update(
            userInteraction=None
        ),
    ],
)
def test_malformed_present_values_raise_value_error(payload, mutate):
    mutate(payload["vulnerabilities"][0]["cve"])
    with pytest.raises(ValueError):
        report_for(payload)


@pytest.mark.parametrize(
    "bad_payload",
    [
        None,
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2020-1234"}}]},
    ],
)
def test_invalid_wrapper_raises_value_error(bad_payload):
    with pytest.raises(ValueError):
        extract_record(bad_payload, CVE_ID)


def test_payload_is_not_mutated(payload):
    before = copy.deepcopy(payload)
    report_for(payload)
    assert payload == before


@pytest.mark.parametrize("variant", [True, 0, 16, "4"])
def test_invalid_variant_is_rejected(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, variant)
