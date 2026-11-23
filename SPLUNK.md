# Splunk candidate searches

**Status: drafts for lab validation.** These searches have not been run against a
Splunk instance. The tested reference implementation is `hunt.py`.

Import `sample_events.jsonl` into a lab index named `auth_lab`, with a JSON
sourcetype named `auth_lab_json`. Use the sample date (2026-11-01) or an appropriate
all-time search range. Verify that the ingestion timestamp includes that range;
rewriting `_time` during a search cannot recover events excluded by the initial
time picker.

The searches use the normalized schema in the README, not field names guaranteed
by a Windows add-on. `spath path=host output=target_host` extracts the destination
from the JSON rather than relying on Splunk's metadata `host` field. The fixture
timestamps use UTC `Z`; adapt parsing if you ingest a different timestamp format.

## AUTH-001: concentrated failures

```spl
index=auth_lab sourcetype=auth_lab_json
| spath
| spath path=host output=target_host
| eval event_id=tonumber(event_id), logon_type=tonumber(logon_type), user=lower(trim(user)), target_host=lower(trim(target_host))
| eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| where event_id=4625 AND in(logon_type,3,10) AND isnotnull(_time)
| sort 0 + _time
| streamstats time_window=5m count AS failure_count min(_time) AS first_failure BY src_ip target_host logon_type user
| where failure_count>=5
| eval rule_id="AUTH-001", attack_hypothesis="T1110.001"
| table _time first_failure rule_id src_ip target_host logon_type user failure_count attack_hypothesis
```

## AUTH-002: failures across many accounts

```spl
index=auth_lab sourcetype=auth_lab_json
| spath
| spath path=host output=target_host
| eval event_id=tonumber(event_id), logon_type=tonumber(logon_type), user=lower(trim(user)), target_host=lower(trim(target_host))
| eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| where event_id=4625 AND in(logon_type,3,10) AND isnotnull(_time)
| sort 0 + _time
| streamstats time_window=5m dc(user) AS account_count count AS failure_count BY src_ip target_host logon_type
| where account_count>=8
| eval rule_id="AUTH-002", attack_hypothesis="T1110.003"
| table _time rule_id src_ip target_host logon_type account_count failure_count attack_hypothesis
```

## Validation checklist

- Confirm the extracted account is the target identity, including its domain.
- Confirm `src_ip`, `target_host`, and `_time` exist and have the expected values.
- Run the sample and a known benign control before enabling any scheduled search.
- Test exact window boundaries and review `streamstats` memory and row limits
  for your Splunk version and event volume.
- These searches return **every qualifying event**, whereas the Python engine
  suppresses a continuing burst. They are not a promise of exact output parity.
  AUTH-003 success correlation is implemented and tested in Python only.
- Set incident grouping and suppression independently of the candidate search.
- Do not infer malicious intent from either count alone.

Reference: [Splunk streamstats documentation](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.3/search-commands/streamstats).
