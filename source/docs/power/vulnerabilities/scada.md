# SCADA server assessment: supervisory system supervises nothing

![SCADA](/_static/images/ot-scada.png)

*Or: How Ponder Discovered That OPC UA's Security Features Were Entirely Optional*

## The supervisory layer

SCADA (Supervisory Control and Data Acquisition) servers are the nerve centres of industrial operations, Ponder noted. They collect data from field devices, present it to operators through interfaces, log everything for historical analysis, and send control commands back to the field. They're the systems that provide visibility into what dozens or hundreds of devices are doing simultaneously.

The UU P&L simulator included a SCADA server running Wonderware System Platform, complete with an OPC UA interface for data integration. OPC UA (Open Platform Communications Unified Architecture) was meant to be the modern, secure protocol for industrial integration. It had encryption options, authentication mechanisms, and security policies.

The question, as always, was whether anyone had actually enabled those security features.

## OPC UA: Security that is not entirely optional

OPC UA was designed to solve the security problems of older industrial protocols. It supported encryption, authentication, and access control. Unfortunately, as Ponder discovered, all of these features were optional, and "optional" in industrial systems typically means "disabled for convenience".

### Understanding OPC UA security

OPC UA has three security modes:

None: No encryption or authentication. Messages pass in cleartext, anyone can connect. This mode exists for backwards compatibility and "testing purposes". In practice, it's used far more widely than manufacturers would like to admit.

Sign: Messages are authenticated but not encrypted. You know who you're talking to, but anyone listening on the network can read everything. Slightly better than None, still not good.

SignAndEncrypt: Full security with authentication and encryption. This is what OPC UA security should look like. It's also what requires certificates, proper configuration, and occasionally breaks when certificates expire.

OPC UA also has authentication options:

Anonymous: Anyone can connect without credentials. No username, no password, no certificate. Just connect and start browsing.

Username/Password: Basic authentication. Better than anonymous, but only if the passwords are actually good.

Certificate-based: Strong authentication using X.509 certificates. Proper PKI, proper security. Also properly complicated to set up.

### Testing the SCADA server

Ponder's first test was simple: could he connect to the SCADA server's OPC UA interface at all? The [OPC UA probe script](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/opcua_readonly_probe.py) attempted an anonymous connection.

```python
# From opcua_readonly_probe.py
client = Client("opc.tcp://127.0.0.1:4840")
async with client:
    # Connected! Now what can we see?
    root = client.get_root_node()
    objects = await root.get_children()
```

It connected immediately. No certificate required. No username requested. No password challenged. The server accepted anonymous connections and provided access to its entire object hierarchy.

"Well," Ponder muttered, "that's not ideal."

### Browsing the server

Once connected, the script traversed the OPC UA server's node tree, discovering what data was available:

```
Objects
├── Server
│   ├── ServerStatus
│   ├── ServiceLevel
│   └── ServerDiagnostics
├── DeviceSet
│   ├── TurbinePLC
│   │   ├── SpeedSetpoint (R/W)
│   │   ├── PowerSetpoint (R/W)
│   │   ├── CurrentSpeed (R/O)
│   │   ├── BearingTemp (R/O)
│   │   └── EmergencyStop (R/W)
│   └── ReactorPLC
│       ├── Temperature (R/O)
│       ├── Pressure (R/O)
│       └── FlowRate (R/O)
└── HistoricalData
    └── [various historian nodes]
```

Every tag, every setpoint, every measurement, all browseable. The script documented:
- Node IDs and browse names
- Data types (Int32, Float, Boolean, etc.)
- Access permissions (readable, writeable, or both)
- Current values

It saved everything to `reports/opcua_browse_<timestamp>.json` for analysis.

Security implication: Complete visibility into SCADA data points. An attacker can enumerate all available tags, understand the system's organisation, and identify which nodes are writable (and therefore controllable).

### Reading live data

Browsing the tree was educational, but the real test was reading actual values:

```python
# Reading turbine speed
speed_node = client.get_node("ns=2;s=TurbinePLC.CurrentSpeed")
speed_value = await speed_node.read_value()
print(f"Current turbine speed: {speed_value} RPM")

# Reading reactor temperature
temp_node = client.get_node("ns=2;s=ReactorPLC.Temperature")
temp_value = await temp_node.read_value()
print(f"Reactor temperature: {temp_value}°C")
```

All values were readable. The SCADA server provided real-time process data without authentication. Ponder could observe every measurement, every setpoint, every control state, all by simply connecting to port 4840.

Security implication: Real-time process monitoring without authentication. An attacker can observe operational patterns, wait for specific conditions, and time attacks for maximum impact.

### The write problem (untested)

Whilst Ponder's testing was strictly read-only, OPC UA also supports writing to nodes. The server's security 
configuration determined what could be written:

```python
# Hypothetical write operation (NOT TESTED)
setpoint_node = client.get_node("ns=2;s=TurbinePLC.SpeedSetpoint")
await setpoint_node.write_value(3600)  # Set new speed target
```

If the server allowed anonymous write access (which some improperly configured servers do), an attacker could:
- Change turbine setpoints
- Modify reactor parameters
- Issue control commands
- Alter configuration data

All without authentication, simply by writing to the appropriate OPC UA nodes.

Security implication: If write access is enabled for anonymous users, complete control of the process is possible through OPC UA. Even if writes require authentication, weak credentials (username/password) are much easier to compromise than proper certificate-based authentication.

### What the security policy said

The OPC UA server's security policy configuration:

```yaml
# From devices.yml - SCADA server configuration
security_policy: None          # No encryption
allow_anonymous: true          # No authentication required
```

The comments in the configuration were revealing: "INSECURE: No encryption (realistic for legacy SCADA systems)".

This wasn't incompetence. This was a deliberate configuration choice, documented and accepted. The security policy was None because enabling encryption would require:
- Generating certificates for the server
- Distributing certificates to all clients
- Maintaining certificate expiry dates
- Troubleshooting certificate validation errors
- Dealing with clients that don't support SignAndEncrypt mode

It was easier to use SecurityPolicy None. It always worked. It never generated certificate errors. It was compatible with everything.

It was also completely insecure, but that was apparently an acceptable trade-off.

### The backup SCADA server

The simulator also included a backup SCADA server on port 4841. This one had proper security configured:

```yaml
# Backup SCADA configuration
security_policy: Basic256Sha256   # Proper encryption
allow_anonymous: false            # Authentication required
certificate: certs/scada_backup.crt
private_key: certs/scada_backup.key
```

Attempting to connect to this server without valid certificates failed immediately. This was what OPC UA security should look like: authentication required, encryption enabled, anonymous access denied.

The fact that the backup server had proper security whilst the primary server didn't was telling. Someone knew how to configure OPC UA securely. They'd chosen not to on the primary server, presumably for the same reasons most facilities make that choice: convenience, compatibility, and "we'll fix it later".

## What the testing revealed

Testing the simulator's SCADA server revealed several uncomfortable truths about OPC UA in practice:

### Security is optional

OPC UA has excellent security features. They're also entirely optional. The protocol works perfectly well with SecurityMode None and anonymous authentication. Many installations use exactly those settings because they're easier.

### Convenience trumps security

Enabling proper OPC UA security requires:
- Certificate generation and distribution
- Certificate lifecycle management
- Troubleshooting certificate errors
- Ensuring all clients support encrypted mode

Or you can set SecurityMode to None and avoid all of those problems. The choice is obvious, even if unfortunate.

### Default allows everything

The default OPC UA server configuration (if improperly configured) allows:
- Anonymous connections
- Complete tag browsing
- Reading all values
- Sometimes writing values

This is the opposite of secure-by-default design. Security requires explicit configuration, and if that configuration isn't done, everything is accessible.

### Read access is still dangerous

Even if write access is disabled, read-only access to OPC UA provides:
- Complete visibility into process operations
- Real-time measurement values
- System organisation and tag structure
- Foundation for planning more sophisticated attacks

An attacker who can read everything knows exactly how the system operates, what the normal ranges are, and when abnormal values might indicate vulnerability.

## The simulator as a teaching tool

Testing the UU P&L simulator's OPC UA server provided hands-on experience with industrial data integration protocols without risking actual infrastructure. The script demonstrates:

Running the test:
```bash
python scripts/vulns/opcua_readonly_probe.py
```

What it reveals:
- Whether anonymous access is allowed
- What tags and nodes are browseable
- What data types are present
- Which nodes are readable/writeable
- Current operational values

Output:
- Console output showing connection status and discovered nodes
- JSON report saved to `reports/opcua_browse_<timestamp>.json`
- Complete documentation of the server's object hierarchy

The test is completely read-only. It doesn't modify any values, doesn't write to any nodes, doesn't change any configurations. It simply connects, browses, reads, and documents what it finds.

## The uncomfortable reality

OPC UA was meant to be the secure successor to older industrial protocols. It has all the right security features: encryption, authentication, access control, certificate management. These features are technically excellent.

They're also optional, complex to configure, and frequently disabled. The result is that many OPC UA servers run with SecurityMode None and anonymous access enabled, which makes them only marginally more secure than the protocols they were meant to replace.

At UU P&L, the primary SCADA server ran with no security because enabling it would have:
- Required certificate generation and distribution
- Broken compatibility with some older clients
- Required staff training on certificate management
- Added troubleshooting complexity

The backup server had proper security configured, proving it was technically possible. But the primary server, the one actually in use, had security disabled for convenience.

This pattern repeats across industrial facilities. OPC UA is capable of being secure. In practice, it's often configured exactly as insecurely as the protocols it replaced, just with more complexity around the insecurity.

The only realistic security measures are compensating controls:
- Network segmentation to restrict who can reach OPC UA servers
- Firewall rules limiting port 4840 access
- Network monitoring to detect unauthorised connections
- Accepting that the protocols themselves aren't providing security

Ponder's testing journal concluded: "OPC UA has excellent security features that nobody uses because they're difficult. 
The result is a protocol that's technically secure and practically insecure. The security is there, sitting in the 
specification, completely optional and usually disabled. This is progress, technically speaking, but not the kind of 
progress that actually makes systems secure."

Further Reading:
- [Vulnerability Assessment Scripts](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/vulns/README.md) - Technical details on OPC UA testing
- [TESTING_CHECKLIST](https://github.com/ninabarzh/power-and-light-sim/tree/main/scripts/TESTING_CHECKLIST.md) - Complete test coverage
- [Protocol Integration Guide](https://github.com/ninabarzh/power-and-light-sim/tree/main/docs/protocol_integration.md) - How OPC UA integrates with devices

The OPC UA reconnaissance script demonstrates real-world reconnaissance techniques against industrial data servers. All testing is read-only but reveals the complete attack surface available to anonymous clients.
