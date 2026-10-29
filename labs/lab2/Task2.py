from __future__ import annotations
import ipaddress
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
)
AUTH_EVENT = re.compile(
    r"sshd\[\d+\]:\s+(?P<status>Failed|Accepted) password for "
    r"(?:(?:invalid|unknown) user )?(?P<username>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2\b"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    status: str
    username: str
    ip: str

@dataclass(frozen=True)
class BruteforceFinding:
    ip: str
    attempts: int
    window_start: datetime
    window_end: datetime
    usernames: dict[str, int]

def _parse_timestamp(line: str, year: int) -> datetime | None:
    prefix = SYSLOG_PREFIX.match(line)
    if prefix is None or prefix.group("month") not in MONTHS:
        return None
    value = f"{year} {prefix.group('month')} {prefix.group('day')} {prefix.group('time')}"
    try:
        return datetime.strptime(value, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def parse_auth_log(path: Path, year: int | None = None) -> tuple[list[AuthEvent], int]:
    if year is None:
        year = datetime.now().year
    events: list[AuthEvent] = []
    line_count = 0

    with path.open("r", encoding="utf-8", errors="replace") as auth_file:
        for line_count, line in enumerate(auth_file, start=1):
            match = AUTH_EVENT.search(line)
            if match is None:
                continue
            timestamp = _parse_timestamp(line, year)
            if timestamp is None:
                continue
            raw_ip = match.group("ip")
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            events.append(
                AuthEvent(
                    timestamp=timestamp,
                    status=match.group("status"),
                    username=match.group("username"),
                    ip=ip,
                )
            )

    return events, line_count

def detect_bruteforce(
    events: list[AuthEvent], threshold: int = 5, window_min: int = 5
) -> list[BruteforceFinding]:
    if threshold <= 0:
        raise ValueError("threshold має бути додатним числом.")
    if window_min <= 0:
        raise ValueError("window_min має бути додатним числом.")

    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.status == "Failed":
            failures_by_ip[event.ip].append(event)

    window = timedelta(minutes=window_min)
    findings: list[BruteforceFinding] = []
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)
        start = 0
        while start < len(failures):
            end = start + 1
            while (
                end < len(failures)
                and failures[end].timestamp - failures[start].timestamp <= window
            ):
                end += 1
            matching_events = failures[start:end]
            if len(matching_events) > threshold:
                findings.append(
                    BruteforceFinding(
                        ip=ip,
                        attempts=len(matching_events),
                        window_start=matching_events[0].timestamp,
                        window_end=matching_events[-1].timestamp,
                        usernames=dict(Counter(event.username for event in matching_events)),
                    )
                )
                start = end
            else:
                start += 1
    return findings

def _build_report(
    events: list[AuthEvent], line_count: int, findings: list[BruteforceFinding]
) -> dict[str, object]:
    successful = sum(event.status == "Accepted" for event in events)
    failed = sum(event.status == "Failed" for event in events)
    time_range = None
    if events:
        timestamps = [event.timestamp for event in events]
        time_range = {
            "start": min(timestamps).isoformat(sep=" "),
            "end": max(timestamps).isoformat(sep=" "),
        }
    return {
        "lines_processed": line_count,
        "events_parsed": len(events),
        "successful_logins": successful,
        "failed_logins": failed,
        "time_range": time_range,
        "findings": [
            {
                "ip": finding.ip,
                "attempts": finding.attempts,
                "window_start": finding.window_start.isoformat(sep=" "),
                "window_end": finding.window_end.isoformat(sep=" "),
                "usernames": finding.usernames,
            }
            for finding in findings
        ],
        "blocked_ips": sorted({finding.ip for finding in findings}),
    }

def _print_report(
    report: dict[str, object], findings: list[BruteforceFinding], threshold: int, window_min: int
) -> None:
    print("=== SSH Bruteforce Detection Results ===")
    print(f"Lines processed: {report['lines_processed']}")
    print(f"Authentication events parsed: {report['events_parsed']}")
    print(f"Successful logins: {report['successful_logins']}")
    print(f"Failed logins: {report['failed_logins']}")
    print(f"Bruteforce threshold: >{threshold} failed attempts in {window_min} minutes")
    time_range = report["time_range"]
    if time_range:
        print(f"Time range: {time_range['start']} - {time_range['end']}")
    if not findings:
        print("No bruteforce activity detected.")
        return

    print("=== Detected Bruteforce Activity ===")
    for finding in findings:
        usernames = ", ".join(
            f"{username} ({count})" for username, count in sorted(finding.usernames.items())
        )
        print(
            f"[ALERT] {finding.ip}: {finding.attempts} failed attempts from "
            f"{finding.window_start:%Y-%m-%d %H:%M:%S} to "
            f"{finding.window_end:%Y-%m-%d %H:%M:%S}; users: {usernames}"
        )
    print("IPs recommended for blocking: " + ", ".join(report["blocked_ips"]))


def run_task2(
    auth_log: Path,
    threshold: int = 5,
    window_min: int = 5,
    output_json: Path | None = None,
) -> dict[str, object]:
    auth_log = Path(auth_log)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    logging.info("Analyzing authentication events in %s...", auth_log)
    try:
        events, line_count = parse_auth_log(auth_log)
        findings = detect_bruteforce(events, threshold, window_min)
    except (OSError, ValueError) as error:
        logging.error("Unable to analyze auth log: %s", error)
        raise SystemExit(1) from error

    report = _build_report(events, line_count, findings)
    logging.info("Processed %s lines and parsed %s authentication events.", line_count, len(events))
    for finding in findings:
        logging.error(
            "Bruteforce detected from %s: %s failures between %s and %s",
            finding.ip,
            finding.attempts,
            finding.window_start,
            finding.window_end,
        )
    _print_report(report, findings, threshold, window_min)

    if output_json is not None:
        output_json = Path(output_json)
        try:
            output_json.parent.mkdir(parents=True, exist_ok=True)
            output_json.write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError as error:
            logging.error("Unable to write JSON report to %s: %s", output_json, error)
            raise SystemExit(1) from error
        logging.info("JSON report saved to %s", output_json)

    return report
