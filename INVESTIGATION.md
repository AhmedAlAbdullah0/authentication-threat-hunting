# Investigation: failed logons followed by success

**Dataset:** generated telemetry in `sample_events.jsonl`  
**Scenario date:** 2026-11-01; all times below are UTC  
**Disposition:** suspicious pattern requiring investigation; no verified compromise

## Question

Does a cluster of failed network logons lead to a successful logon for the same
account, from the same source, to the same destination? Separately, does one
source attempt many accounts in a short period?

## Evidence timeline

| UTC | Source | Destination | Identity | Observation |
|---|---|---|---|---|
| 09:04:50–09:05:05 | 203.0.113.10 | lab-win01 | lab\\alex | Six event-4625 failures, logon type 3 |
| 09:05:02 | 203.0.113.10 | lab-win01 | lab\\alex | AUTH-001 crosses the five-failure threshold |
| 09:05:10 | 203.0.113.10 | lab-win01 | lab\\alex | Event 4624; AUTH-003 correlates all six earlier failures |
| 09:20:00–09:21:10 | 198.51.100.20 | lab-win02 | Eight distinct lab accounts | AUTH-002 identifies multi-account failures |
| 09:40:00–09:40:20 | 192.0.2.30 | lab-win01 | lab\\blair | Two failures then success; below threshold |

These are documentation-range IPs and invented lab accounts, not indicators
from an actual intrusion. Findings are reproducible with the README commands.

## Reasoning

The first sequence deserves priority because success follows a dense failure
cluster and matches all four correlation fields. Matching only a username or
an IP could wrongly join activity from different hosts or logon types.

A successful logon is evidence of a session, not proof of unauthorized access.
An authorized user correcting a password could produce a similar sequence.
The supplied data cannot decide between those explanations.

The second sequence is consistent with a password-spraying hypothesis
(T1110.003), but the dataset contains no passwords, authentication-package data,
or account-owner confirmation. Describe the result as **spray-like behavior**,
not a confirmed spray attack.

## Next pivots before disposition

1. Check account-owner activity and approved support/change windows.
2. Resolve the source through VPN, DHCP, and asset context. A shared source does
   not prove a common actor.
3. Review the complete 4625 records for status/substatus, account lockout, and
   authentication-package details. Those fields are absent from this normalized
   fixture and cannot be inferred.
4. Pivot from the successful session into endpoint process, network, and privilege
   telemetry using the destination host, account, and precise time. The fixture
   does not contain those additional event sources.
5. Expand the search for other accounts, hosts, source addresses, and lower-rate
   failures. Document whether audit coverage is complete.

Containment should follow confirmed context and the organization's response
process; this tool does not disable accounts, isolate hosts, or block IPs.

## What was actually validated

The offline Python run produces exactly three findings from 39 generated events.
The low-volume retry remains unflagged. Behavioral tests cover window boundaries,
success ordering, suppression, isolation of correlation keys, and invalid inputs.
The event set and outputs are inspectable; there is no claim of production
coverage or a completed live Splunk deployment.
