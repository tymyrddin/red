# Detecting OT attacks

OT detection operates across three layers that rarely share data: IT security monitoring (SIEM, EDR), OT network monitoring (passive protocol inspection), and process monitoring (historian data and operator alarms). The attacks that are hardest to detect are the ones that stay within the bounds of all three layers simultaneously. Effective detection requires integrating data across the boundary.

## IT/OT boundary crossing detection

The earliest detection opportunity for the dominant attack path (IT to OT lateral movement) is at the IT layer, before the attacker reaches OT at all.

Authentication events on historian servers and OT jump hosts should be correlated with the user's normal access pattern. An engineer who does not normally access the historian interactively, or who accesses it from an unusual source IP, warrants investigation.

Firewall logs at the IT/OT boundary should alert on any new source IP attempting to reach OT protocol ports (502, 44818, 102, 4840, 20000, 47808). Legitimate SCADA polling comes from a fixed set of source addresses; any new source is anomalous.

```
Alert: TCP connection to port 502 from any source not in the approved SCADA master list
Alert: Successful authentication to OT jump host from a source outside the engineering VLAN
Alert: New device (MAC address) observed on any OT segment
```

## OT protocol monitoring

Passive OT network monitoring (Claroty, Dragos, Nozomi, or open-source alternatives like Zeek with OT protocol dissectors) builds a baseline of normal communication patterns. Anomaly detection covers:

- New IP address sending commands to a known PLC.
- Function codes that have not previously been observed from a given source.
- Write operations to addresses that are only read by the legitimate SCADA system.
- Commands sent outside the normal polling interval.

These detections are effective against naive attacks but can be evaded by an attacker who has observed the baseline traffic and mimics it. The mitigations for evasion-aware attacks require process-layer correlation.

## Process deviation detection

Integrating historian data with security alerting is the detection layer that covers protocol-compliant manipulation. The key metrics:

- Process variables that change outside their historical variance without a corresponding operator action or change order.
- Setpoint values that differ from the SCADA-reported setpoints (indicating a write that bypassed the SCADA system).
- Process outcomes that deviate from the expected trajectory for the current operating conditions.

This integration requires cooperation between OT security, process engineering, and operations teams. The security monitoring platform needs access to historian data; the process engineers need to define the expected variance bounds; the operations team needs to review anomalies that could be process variation rather than attack.

## Engineering software activity monitoring

Engineering software connections to PLCs are inherently privileged operations. Every time TIA Portal or Studio 5000 connects to a PLC in online mode, it should generate a log entry that is reviewed. This requires:

- Enabling audit logging in the engineering software where available.
- Configuring the PLC or its managed switch to log successful connections on engineering ports (S7comm port 102, EtherNet/IP port 44818).
- Correlating engineering software connection events with change management records: any connection that is not associated with an approved change order is anomalous.

Most OT environments do not currently log engineering software connections at all. Establishing this logging is a foundational detection improvement that does not require network redesign.

## The integrated detection picture

A mature OT detection programme generates alerts from all three layers and correlates them. A sequence of: new source IP connecting to historian, followed by engineering software connection to a PLC, followed by a process variable moving outside its historical variance, is a high-confidence incident indicator. Any single one of those events might be benign; the sequence is not.

The time-to-detect for this attack pattern in most organisations is measured in days or weeks, because the three layers are monitored by different teams who do not share data. Closing this gap is the primary defensive improvement available to OT environments, and it requires less capital investment than network redesign.
