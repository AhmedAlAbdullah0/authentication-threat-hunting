# Authentication Threat Hunting

**From failed logons to an evidence-based investigation.**

A reproducible, offline project for detecting suspicious Windows authentication
patterns in normalized event data. It combines a dependency-free Python detector,
behavioral tests, Splunk search drafts, and an investigation of synthetic telemetry.

> **Scope:** generated lab data, not a production incident or a capture from an
> employer. Python execution is verified; the Splunk drafts have not been executed
> against a Splunk instance. See [validation](VALIDATION.md).

## Start here

| Goal | File |
|---|---|
| Run the detection engine | [hunt.py](hunt.py) |
| Review the case and reasoning | [INVESTIGATION.md](INVESTIGATION.md) |
| Read Splunk candidate searches | [SPLUNK.md](SPLUNK.md) |
| Inspect the input and expected findings | [sample_events.jsonl](sample_events.jsonl) / [expected_alerts.json](expected_alerts.json) |
| Check behavior and edge cases | [test_hunt.py](test_hunt.py) |
| Rebuild the synthetic telemetry | [make_sample.py](make_sample.py) |

## Run in under a minute

Requires **Python 3.10+**. No packages, API keys, SIEM, or Windows host required.

```bash
git clone https://github.com/AhmedAlAbdullah0/authentication-threat-hunting.git
cd authentication-threat-hunting
python hunt.py sample_events.jsonl --output alerts.json
python -m unittest -v
```

On Windows, use `py` instead of `python` if that is your installed launcher.
The CLI writes findings to the selected file, and writes its summary to stderr:

```text
Loaded 39 events; generated 3 findings.
```

| Rule | Result in the sample | Priority |
|---|---|---|
| AUTH-001 | Five failures for one account trigger at 09:05:02 UTC | Medium |
| AUTH-003 | Six failures followed by a success at 09:05:10 UTC | High |
| AUTH-002 | Eight accounts receive failed logons from one source | Medium |

The two-failure retry followed by a success does **not** trigger. Successful
background logons and interactive logons (type 2) do not create findings.

## Detection design

| Rule | Condition within the default rolling 300-second window | Correlation key | ATT&CK hypothesis |
|---|---|---|---|
| AUTH-001 | At least 5 failed logons | Source IP + target host + logon type + account | T1110.001 |
| AUTH-002 | Failed logons against at least 8 distinct accounts | Source IP + target host + logon type | T1110.003 |
| AUTH-003 | A successful logon after at least 5 failures | Same source IP, host, logon type, and account | T1110.001 |

The ATT&CK IDs describe investigative hypotheses. Neither password reuse nor
unauthorized access can be established from these fields alone.

### Why a rolling window?

The sample burst starts at 09:04:50 and continues past 09:05:00. A fixed five-minute
bucket splits those six events into four and two; neither bucket reaches five.
A rolling window catches the sequence across that boundary.

### Ordering and suppression

- Input may arrive out of order; the detector sorts timestamps in UTC.
- Failure windows include the lower and upper boundary. For a success at `t`,
  only failures in `[t - window, t)` qualify. Same-time failures cannot establish
  that they preceded the success.
- Failure and multi-account findings emit when a threshold is crossed, and rearm
  after the active window falls below it. Findings capture the crossing window,
  not a retrospective total of the entire incident.
- Each qualifying success emits a finding. This deliberately preserves evidence
  of repeated successes; downstream incident grouping is a separate step.

## Input contract

One JSON object per line, with these required fields:

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | string | ISO 8601 with `Z` or an explicit UTC offset |
| `event_id` | integer | 4624 = successful logon; 4625 = failed logon |
| `src_ip` | string | Valid IPv4 or IPv6 source address |
| `user` | string | Domain-qualified target identity, e.g. `lab\\alex` |
| `host` | string | Destination computer containing the event |
| `logon_type` | integer | Only type 3 (network) and type 10 (remote interactive) are in scope |

Normalize Windows XML or your SIEM export before using this tool. For the target
identity, use `TargetDomainName` plus `TargetUserName`, not the event's subject
account. Preserve domain boundaries to avoid mixing unrelated accounts. IP
placeholders such as `-` need triage during normalization; they are rejected here.
This is **not** an EVTX parser. Other integer event IDs/logon types are accepted
as normalized input but ignored by detection. Malformed rows fail the run with a
line number and exit status 2; successful runs return 0 even with findings.

## Tune a lab run

```bash
python hunt.py sample_events.jsonl --window-seconds 600 --failure-threshold 6 --user-threshold 10
python hunt.py sample_events.jsonl --allow-ip 203.0.113.10
python make_sample.py
```

Allowlisting is explicit, exact-IP only, and applies to all three rules. Review
the full activity before excluding a shared gateway or administrator source.

## Limits and next validation steps

- Synthetic data demonstrates behavior, not real-world detection accuracy.
- Shared NAT, password resets, mistyped credentials, stale service passwords, and
  scanners can cause similar patterns. Source IP is not a person or device identity.
- Multi-account failures are spray-like; the log does not disclose the passwords
  used. Slow or distributed attempts and attempts spread across hosts can evade
  these intentionally narrow rules.
- Audit policy, event loss, clock skew, duplicate ingestion, account aliases, and
  IPv4-mapped IPv6 representations affect results. This version does not deduplicate
  source records or join identity aliases. Preserve unique record IDs upstream.
- The entire input is held in memory. This is a small offline analysis tool, not
  a streaming service or an enterprise-scale benchmark.
- Validate SPL extraction, time parsing, window limits, false positives, and alert
  suppression in a lab before scheduling a SIEM detection.

## References

- [Microsoft: successful logon event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Microsoft: failed logon event 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK: password guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK: password spraying](https://attack.mitre.org/techniques/T1110/003/)
- [Splunk: streamstats](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.3/search-commands/streamstats)
