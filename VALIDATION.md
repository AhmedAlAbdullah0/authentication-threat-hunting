# Validation record

Recorded 2026-11-23 using Python 3.12.14 in a Linux execution environment.

| Check | Command | Observed result |
|---|---|---|
| Deterministic sample generation | `python make_sample.py` | 39 synthetic events |
| Offline detection | `python hunt.py sample_events.jsonl --output expected_alerts.json` | 3 findings |
| Automated behavior checks | `python -m unittest -v` | 20 tests passed |

The tests exercise both positive and negative behavior: crossing thresholds,
window inclusion and expiry, chronological ordering, independent correlation
keys, allowlisting, distinct-account counting, malformed inputs, and the CLI.
`expected_alerts.json` is a committed output snapshot; the independent behavioral
tests check the underlying conditions rather than relying only on that snapshot.

## Not yet validated

- Python 3.10/3.11 or a Windows host; the code uses Python 3.10-compatible syntax,
  but the recorded execution used 3.12 only.
- Real Windows event collection, EVTX/XML normalization, or live organization data.
- Splunk ingestion, execution of the draft searches, or scheduled alerting.
- Production-scale throughput, false-positive rates, detection recall, or resilience
  to event loss and duplicate ingestion.

No results from these unperformed checks are implied by this repository.
