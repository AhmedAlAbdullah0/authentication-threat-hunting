import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import random
import tempfile
import unittest

from hunt import detect, load_events, main, parse_event


BASE = datetime(2026, 11, 1, tzinfo=timezone.utc)


def event(seconds, event_id=4625, **overrides):
    row = dict(timestamp=(BASE + timedelta(seconds=seconds)).isoformat(),
               event_id=event_id, src_ip="203.0.113.10", user="lab\\alex",
               host="lab-win01", logon_type=3)
    row.update(overrides)
    return parse_event(row)


class DetectionTests(unittest.TestCase):
    def test_fixture_matches_committed_results(self):
        root = Path(__file__).parent
        expected = json.loads((root / "expected_alerts.json").read_text(encoding="utf-8"))
        self.assertEqual(detect(load_events(root / "sample_events.jsonl")), expected)

    def test_failure_threshold_crossing_is_deduplicated(self):
        alerts = detect([event(i) for i in range(10)])
        self.assertEqual([item["rule_id"] for item in alerts], ["AUTH-001"])
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_later_burst_rearms(self):
        self.assertEqual(len(detect([event(i) for i in [0, 1, 2, 3, 4, 601, 602, 603, 604, 605]])), 2)

    def test_window_lower_bound_is_included(self):
        self.assertEqual(len(detect([event(i) for i in [0, 20, 40, 60, 300]])), 1)

    def test_outside_window_does_not_qualify(self):
        self.assertEqual(detect([event(i) for i in [0, 20, 40, 60, 301]]), [])

    def test_success_must_follow_failures(self):
        alerts = detect([event(0, 4624)] + [event(i) for i in range(1, 6)])
        self.assertNotIn("AUTH-003", [item["rule_id"] for item in alerts])

    def test_same_timestamp_is_not_ordered_before_success(self):
        alerts = detect([event(0) for _ in range(5)] + [event(0, 4624)])
        self.assertEqual([item["rule_id"] for item in alerts], ["AUTH-001"])

    def test_success_after_failure_is_high_priority(self):
        alerts = detect([event(i) for i in range(5)] + [event(5, 4624)])
        self.assertEqual(alerts[-1]["rule_id"], "AUTH-003")
        self.assertEqual(alerts[-1]["severity"], "high")

    def test_success_outside_window_is_not_correlated(self):
        alerts = detect([event(i) for i in range(5)] + [event(305, 4624)])
        self.assertEqual([item["rule_id"] for item in alerts], ["AUTH-001"])

    def test_distinct_users_are_required_for_spray(self):
        alerts = detect([event(i, user=f"lab\\user{i}") for i in range(8)])
        self.assertEqual([item["rule_id"] for item in alerts], ["AUTH-002"])

    def test_source_host_user_and_logon_type_are_not_mixed(self):
        failures = [event(i) for i in range(5)]
        for change in [dict(src_ip="203.0.113.11"), dict(host="lab-win02"),
                       dict(user="lab\\blair"), dict(logon_type=10)]:
            with self.subTest(change=change):
                alerts = detect(failures + [event(10, 4624, **change)])
                self.assertNotIn("AUTH-003", [item["rule_id"] for item in alerts])

    def test_spray_does_not_mix_hosts(self):
        self.assertEqual(detect([event(i, user=f"lab\\user{i}", host=f"host{i % 2}")
                                 for i in range(8)]), [])

    def test_interactive_logons_and_other_events_are_out_of_scope(self):
        self.assertEqual(detect([event(i, logon_type=2) for i in range(8)]), [])
        self.assertEqual(detect([event(i, event_id=4648) for i in range(8)]), [])

    def test_allowlist_is_exact(self):
        self.assertEqual(detect([event(i) for i in range(5)], allow_ips=("203.0.113.10",)), [])
        self.assertEqual(len(detect([event(i) for i in range(5)], allow_ips=("203.0.113.11",))), 1)

    def test_input_order_does_not_change_findings(self):
        events = [event(i) for i in range(5)] + [event(10, 4624)]
        expected = detect(events)
        random.Random(42).shuffle(events)
        self.assertEqual(detect(events), expected)

    def test_case_and_timezones_are_normalized(self):
        a = event(0, user="LAB\\ALEX", host="LAB-WIN01")
        b = event(0, timestamp="2026-11-01T03:00:00+03:00")
        self.assertEqual(a, b)

    def test_invalid_schema_is_rejected(self):
        for change in [dict(timestamp="2026-11-01T00:00:00"), dict(src_ip="-"),
                       dict(event_id=True), dict(event_id="4625"), dict(user=""),
                       dict(host=None)]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                event(0, **change)

    def test_invalid_thresholds_are_rejected(self):
        for options in [dict(window_seconds=0), dict(failure_threshold=1), dict(user_threshold=1)]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                detect([], **options)

    def test_loader_identifies_bad_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("\n{not json}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                load_events(path)

    def test_cli_writes_output_and_errors_are_nonzero(self):
        root = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            output = Path(directory) / "alerts.json"
            self.assertEqual(main([str(root / "sample_events.jsonl"), "--output", str(output)]), 0)
            self.assertEqual(len(json.loads(output.read_text(encoding="utf-8"))), 3)
            self.assertEqual(main([str(root / "missing.jsonl")]), 2)


if __name__ == "__main__":
    unittest.main()
