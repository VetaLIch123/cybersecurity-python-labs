"""Validate NVD responses and apply the configured CVSS v3.1 variant rule."""

from __future__ import annotations

import math
from typing import Any

VARIANT_RULES: dict[int, dict[str, Any]] = {
    1: {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
    2: {"threshold": 8.0, "field": "attackComplexity", "expected": "LOW"},
    3: {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"},
    4: {"threshold": 8.0, "field": "userInteraction", "expected": "NONE"},
    5: {"threshold": 7.0, "field": "confidentialityImpact", "expected": "HIGH"},
    6: {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
    7: {"threshold": 7.0, "field": "availabilityImpact", "expected": "HIGH"},
    8: {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    9: {"threshold": 5.0, "field": "attackVector", "expected": "LOCAL"},
    10: {"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"},
    11: {"threshold": 6.0, "field": "userInteraction", "expected": "REQUIRED"},
    12: {"threshold": 6.0, "field": "confidentialityImpact", "expected": "LOW"},
    13: {"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"},
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
    15: {"threshold": 8.0, "field": "attackComplexity", "expected": "HIGH"},
}

ALLOWED_VALUES = {
    "attackVector": {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"},
    "attackComplexity": {"LOW", "HIGH"},
    "privilegesRequired": {"NONE", "LOW", "HIGH"},
    "userInteraction": {"NONE", "REQUIRED"},
    "scope": {"UNCHANGED", "CHANGED"},
    "confidentialityImpact": {"NONE", "LOW", "HIGH"},
    "integrityImpact": {"NONE", "LOW", "HIGH"},
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def _required_string(mapping: dict[str, Any], key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {context}.{key} має бути непорожнім рядком.")
    return value


def _optional_string(mapping: dict[str, Any], key: str, context: str) -> str | None:
    if key not in mapping:
        return None
    return _required_string(mapping, key, context)


def _finite_score(value: Any) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Поле cvssData.baseScore має бути числом від 0 до 10.")
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError(
            "Поле cvssData.baseScore має бути скінченним числом від 0 до 10."
        )
    return value


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Validate an NVD wrapper and return one normalized CVE record or None.

    The record contains description, status, selected CVSS metric and its
    ``cvssData``. Scores are deliberately left uninterpreted until a variant
    rule is applied by :func:`build_report`.
    """
    if not isinstance(payload, dict):
        raise ValueError("Відповідь NVD має бути JSON-об'єктом.")
    if "vulnerabilities" not in payload or not isinstance(
        payload["vulnerabilities"], list
    ):
        raise ValueError("Поле vulnerabilities має бути списком.")
    vulnerabilities = payload["vulnerabilities"]
    if len(vulnerabilities) > 1:
        raise ValueError("Для точного CVE-запиту очікується не більше одного запису.")
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("Елемент vulnerabilities має містити об'єкт cve.")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор у відповіді NVD не збігається із запитаним.")

    status = _optional_string(cve, "vulnStatus", "cve")
    description = None
    if "descriptions" in cve:
        descriptions = cve["descriptions"]
        if not isinstance(descriptions, list):
            raise ValueError("Поле cve.descriptions має бути списком.")
        for entry in descriptions:
            if not isinstance(entry, dict):
                raise ValueError("Елементи cve.descriptions мають бути об'єктами.")
            lang = entry.get("lang")
            if not isinstance(lang, str):
                raise ValueError("Поле cve.descriptions[].lang має бути рядком.")
            value = entry.get("value")
            if not isinstance(value, str):
                raise ValueError("Поле cve.descriptions[].value має бути рядком.")
            if lang.lower() == "en" and value.strip() and description is None:
                description = value

    record: dict[str, Any] = {
        "description": description,
        "vuln_status": status,
        "score": None,
        "score_source": None,
        "cvss_version": None,
        "vector": None,
        "observed": None,
    }
    if status is None or status == "Rejected":
        return record

    if "metrics" not in cve:
        return record
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("Поле cve.metrics має бути об'єктом.")
    if "cvssMetricV31" not in metrics:
        return record
    metric_list = metrics["cvssMetricV31"]
    if not isinstance(metric_list, list):
        raise ValueError("Поле metrics.cvssMetricV31 має бути списком.")
    if not metric_list:
        return record
    if any(not isinstance(metric, dict) for metric in metric_list):
        raise ValueError("Елементи metrics.cvssMetricV31 мають бути об'єктами.")

    selected = next(
        (m for m in metric_list if m.get("type") == "Primary"), metric_list[0]
    )
    if not isinstance(selected.get("cvssData"), dict):
        raise ValueError("Поле вибраної оцінки cvssData має бути об'єктом.")
    cvss_data = selected["cvssData"]
    record.update(
        score=_finite_score(cvss_data.get("baseScore")),
        score_source=_optional_string(selected, "source", "cvssMetricV31[]"),
        cvss_version=_optional_string(cvss_data, "version", "cvssData"),
        vector=_optional_string(cvss_data, "vectorString", "cvssData"),
    )
    if record["cvss_version"] is not None and record["cvss_version"] != "3.1":
        raise ValueError("Підтримується лише cvssData.version '3.1'.")
    record["_cvss_data"] = cvss_data
    return record


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Apply one variant rule and return the stable JSON report structure."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15.")
    rule = VARIANT_RULES[variant].copy()
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": rule,
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    if not isinstance(record, dict):
        raise ValueError("Внутрішній запис має бути об'єктом або None.")
    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    if record["vuln_status"] is None:
        report["decision"] = "insufficient_data"
        return report
    if record.get("score") is None:
        report["decision"] = "insufficient_data"
        return report

    report.update(
        cvss_version=record["cvss_version"],
        score=record["score"],
        score_source=record["score_source"],
        vector=record["vector"],
    )
    cvss_data = record.get("_cvss_data")
    field = rule["field"]
    if not isinstance(cvss_data, dict):
        raise ValueError("У записі відсутні дані вибраної оцінки CVSS.")
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report
    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"Поле cvssData.{field} має недопустиме значення.")
    report["observed"] = observed
    report["decision"] = (
        "review"
        if record["score"] >= rule["threshold"] and observed == rule["expected"]
        else "other"
    )
    return report
