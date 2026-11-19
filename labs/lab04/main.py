"""Command-line interface for the Lab 04 NVD inspection utility."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from shared.student import VARIANT_NUMBER

from labs.lab04 import analysis, api_client

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def _cve_argument(value: str) -> str:
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("CVE має відповідати формату CVE-YYYY-NNNN.")
    return value


def load_response(path: str | Path) -> Any:
    """Read and decode a UTF-8 JSON response from a local file."""
    with Path(path).open("r", encoding="utf-8") as source:
        return json.load(source)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return 0 on a report, 1 on data/API errors."""
    parser = argparse.ArgumentParser(description="Перегляд CVE з NVD API 2.0")
    parser.add_argument(
        "--cve", required=True, type=_cve_argument, help="Ідентифікатор CVE"
    )
    parser.add_argument("--input", help="Локальний JSON-файл відповіді NVD")
    args = parser.parse_args(argv)

    if (
        isinstance(VARIANT_NUMBER, bool)
        or not isinstance(VARIANT_NUMBER, int)
        or not 1 <= VARIANT_NUMBER <= 15
    ):
        print(
            "Помилка: shared.student.VARIANT_NUMBER має бути цілим числом від 1 до 15.",
            file=sys.stderr,
        )
        return 2

    try:
        payload = (
            load_response(args.input)
            if args.input
            else api_client.fetch_response(args.cve)
        )
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except api_client.APIClientError as exc:
        print(f"Помилка API: {exc}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError) as exc:
        print(f"Помилка читання файла: {exc.__class__.__name__}.", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Помилка: файл містить некоректний JSON.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Помилка даних: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
