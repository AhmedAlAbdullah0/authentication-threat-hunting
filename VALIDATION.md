# Validation record

Recorded 2026-11-23 using Python 3.12.14 in a Linux execution environment.

| Check | Command | Observed result |
|---|---|---|
| Deterministic sample generation | `python make_sample.py` | 39 synthetic events |
| Offline detection | `python hunt.py sample_events.jsonl --output expected_alerts.json` | 3 findings |
| Automated behavior checks | `python -m unittest -v` | 20 tests passed |
| GitHub Actions matrix | Python 3.10 and 3.12 on Ubuntu 24.04 and Windows Server 2022 | All 4 jobs passed |

The [first matrix run](https://github.com/AhmedAlAbdullah0/authentication-threat-hunting/actions/runs/45142020524)
passed for commit `03b3c7f975877eee124c108e57447558524d3767`. It runs the behavioral
tests and sample CLI investigation. The [Validation workflow](https://github.com/AhmedAlAbdullah0/authentication-threat-hunting/actions/workflows/validation.yml)
records the current result for subsequent changes.

The tests exercise both positive and negative behavior: crossing thresholds,
window inclusion and expiry, chronological ordering, independent correlation
keys, allowlisting, distinct-account counting, malformed inputs, and the CLI.
`expected_alerts.json` is a committed output snapshot; the independent behavioral
tests check the underlying conditions rather than relying only on that snapshot.

## Not yet validated

- Python 3.11 or interpreter/platform combinations outside the checked matrix.
- Real Windows event collection, EVTX/XML normalization, or live organization data.
- Splunk ingestion, execution of the draft searches, or scheduled alerting.
- Production-scale throughput, false-positive rates, detection recall, or resilience
  to event loss and duplicate ingestion.

No results from these unperformed checks are implied by this repository.
