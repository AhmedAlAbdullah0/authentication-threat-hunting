"""Offline authentication hunting on normalized JSONL. Python 3.10+, stdlib only."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import sys


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    src_ip: str
    user: str
    host: str
    logon_type: int


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_event(row: dict) -> Event:
    if not isinstance(row, dict):
        raise ValueError("each line must contain a JSON object")
    try:
        if not isinstance(row["timestamp"], str) or not isinstance(row["src_ip"], str):
            raise ValueError("timestamp and src_ip must be strings")
        timestamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("timestamp must include Z or a UTC offset")
        for field in ("event_id", "logon_type"):
            if isinstance(row[field], bool) or not isinstance(row[field], int):
                raise ValueError(f"{field} must be a JSON integer")
        user, host = row["user"], row["host"]
        if not isinstance(user, str) or not isinstance(host, str):
            raise ValueError("user and host must be strings")
        if not user.strip() or not host.strip():
            raise ValueError("user and host must not be empty")
        return Event(timestamp.astimezone(timezone.utc), row["event_id"],
                     str(ipaddress.ip_address(row["src_ip"])), user.strip().casefold(),
                     host.strip().casefold(), row["logon_type"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid normalized event: {exc}") from exc


def load_events(path: Path) -> list[Event]:
    events = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                events.append(parse_event(json.loads(line)))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"line {line_number}: {exc}") from exc
    return events


def finding(rule: str, events: list[Event], *, success: Event | None = None) -> dict:
    last = success or events[-1]
    return {
        "rule_id": rule,
        "severity": "high" if success else "medium",
        "attack_hypothesis": "T1110.003" if rule == "AUTH-002" else "T1110.001",
        "src_ip": last.src_ip,
        "host": last.host,
        "logon_type": last.logon_type,
        "users": sorted({event.user for event in events}),
        "window_start": utc(events[0].timestamp),
        "window_end": utc(last.timestamp),
        "failure_count": len(events),
        "success_count": 1 if success else 0,
        "assessment": "Investigate; this pattern alone does not establish compromise.",
    }


def detect(events: list[Event], *, window_seconds: int = 300,
           failure_threshold: int = 5, user_threshold: int = 8,
           allow_ips: tuple[str, ...] = ()) -> list[dict]:
    """Emit on threshold crossings and every qualifying success. No network access.

    Failure windows include both ends. Success windows include the lower bound
    and exclude failures with the exact same timestamp as the success.
    """
    if window_seconds < 1 or failure_threshold < 2 or user_threshold < 2:
        raise ValueError("window must be positive; thresholds must be at least 2")
    allowed = {str(ipaddress.ip_address(ip)) for ip in allow_ips}
    relevant = sorted((event for event in events
                       if event.event_id in (4624, 4625)
                       and event.logon_type in (3, 10)
                       and event.src_ip not in allowed), key=lambda event: event.timestamp)
    per_account = defaultdict(list)
    per_source = defaultdict(list)
    for event in relevant:
        per_account[(event.src_ip, event.host, event.logon_type, event.user)].append(event)
        if event.event_id == 4625:
            per_source[(event.src_ip, event.host, event.logon_type)].append(event)
    alerts = []
    window = timedelta(seconds=window_seconds)
    for group in per_account.values():
        failures = deque()
        burst_active = False
        for event in group:
            cutoff = event.timestamp - window
            while failures and failures[0].timestamp < cutoff:
                failures.popleft()
            if len(failures) < failure_threshold:
                burst_active = False
            if event.event_id == 4625:
                failures.append(event)
                if len(failures) >= failure_threshold and not burst_active:
                    alerts.append(finding("AUTH-001", list(failures)))
                    burst_active = True
            else:
                preceding = [item for item in failures if item.timestamp < event.timestamp]
                if len(preceding) >= failure_threshold:
                    alerts.append(finding("AUTH-003", preceding, success=event))
    for group in per_source.values():
        failures = deque()
        counts = Counter()
        spray_active = False
        for event in group:
            cutoff = event.timestamp - window
            while failures and failures[0].timestamp < cutoff:
                removed = failures.popleft()
                counts[removed.user] -= 1
                if counts[removed.user] == 0:
                    del counts[removed.user]
            if len(counts) < user_threshold:
                spray_active = False
            failures.append(event)
            counts[event.user] += 1
            if len(counts) >= user_threshold and not spray_active:
                alerts.append(finding("AUTH-002", list(failures)))
                spray_active = True
    return sorted(alerts, key=lambda item: (datetime.fromisoformat(item["window_end"].replace("Z", "+00:00")), item["rule_id"],
                                          item["src_ip"], item["host"], item["users"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="normalized JSONL event file")
    parser.add_argument("--output", type=Path, help="write JSON findings to this file")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--user-threshold", type=int, default=8)
    parser.add_argument("--allow-ip", action="append", default=[], help="explicit trusted source; repeatable")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        alerts = detect(events, window_seconds=args.window_seconds,
                        failure_threshold=args.failure_threshold,
                        user_threshold=args.user_threshold, allow_ips=tuple(args.allow_ip))
        result = json.dumps(alerts, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        print(f"Loaded {len(events)} events; generated {len(alerts)} findings.", file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
