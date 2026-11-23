"""Create deterministic normalized test telemetry; never connects to a target."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def make_sample():
    base = datetime(2026, 11, 1, 9, tzinfo=timezone.utc)
    rows = []

    def add(seconds, event_id, src_ip, user, host="lab-win01", logon_type=3):
        rows.append(dict(timestamp=(base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
                         event_id=event_id, src_ip=src_ip, user=user, host=host, logon_type=logon_type))

    # A burst crossing the 09:05 fixed-bucket boundary, then a success.
    for seconds in [290, 293, 296, 299, 302, 305]:
        add(seconds, 4625, "203.0.113.10", "lab\\alex")
    add(310, 4624, "203.0.113.10", "lab\\alex")
    # Multi-account failures: spray-like behavior; no passwords are recorded.
    for index in range(8):
        add(1200 + 10 * index, 4625, "198.51.100.20", f"lab\\user{index + 1:02d}", "lab-win02")
    # A normal retry sequence that must remain below the failure threshold.
    for seconds in [2400, 2410]:
        add(seconds, 4625, "192.0.2.30", "lab\\blair")
    add(2420, 4624, "192.0.2.30", "lab\\blair")
    # Benign successful activity across several accounts.
    for index in range(15):
        add(3600 + 30 * index, 4624, "192.0.2.40", f"lab\\employee{index % 3 + 1}")
    # Interactive activity is explicitly outside this remote-logon detector.
    for index in range(6):
        add(4500 + index, 4625, "192.0.2.50", "lab\\localuser", logon_type=2)
    return sorted(rows, key=lambda row: row["timestamp"])


if __name__ == "__main__":
    output = Path(__file__).with_name("sample_events.jsonl")
    rows = make_sample()
    output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    print(f"Wrote {len(rows)} synthetic events to {output.name}.")
