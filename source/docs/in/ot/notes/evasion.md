# Low-and-slow: OT evasion and blending

The flashy attack is a liability in OT environments. A sudden change to a process setpoint triggers alarms, operator attention, and investigation. The effective OT attack is the one that looks like a process drift, a sensor reading within normal variance, or routine maintenance activity. Operators trust their systems, and the most dangerous manipulation is the one that stays within the bounds of what operators expect to see.

## Staying within protocol norms

OT protocol monitoring, where it exists, looks for anomalous function codes, unexpected device addresses, or messages from unauthorised source addresses. Attacks that use the same function codes as the legitimate SCADA polling traffic, from an IP address that has been on the network long enough to appear in the baseline, do not stand out at the protocol level.

The practical approach is to observe legitimate traffic passively before sending any commands. A PCAP of the SCADA-to-PLC communication reveals the polling interval, the specific register addresses that are read and written, and the range of values that are written. Staying within the observed write range and timing commands to coincide with legitimate write activity makes the manipulation look like part of the normal SCADA operation.

## Gradual deviation instead of step changes

A setpoint that changes by 40% in a single write will trigger an operator alarm if any HMI limit check is configured for that value. The same cumulative change applied over hours in small increments stays within the operating band and does not trigger limit alarms. The process drifts; the operator notices a trend but attributes it to process variation or feed changes.

This technique requires patience and an understanding of the target process: which parameters have alarm limits, what the natural variation looks like, and how much deviation can accumulate before it affects process outcomes or product quality. The engineering project file provides this understanding; the historian provides the baseline variation data.

## Timing with maintenance windows

Engineering changes to PLCs require the device to enter programming mode, which generates an event in the SCADA event log. Scheduling a logic download during a maintenance window, when engineering changes are expected and event logs are full of similar entries, reduces the visibility of the unauthorised change. Alternatively, if the engineering software can be used to make changes that do not require a download (online editing in Siemens TIA Portal and Rockwell Studio 5000 allows some parameter changes without a full download), the download event does not appear in the log at all.

## Protocol-aware detection and its limits

Modern OT network monitoring tools (Claroty, Dragos, Nozomi) perform deep packet inspection of industrial protocols and build a baseline of normal communication patterns. Anomaly detection flags:

- New device or IP address sending commands.
- Function codes that have not been observed in the baseline.
- Write operations to addresses that are normally read-only from the SCADA perspective.
- Out-of-range values in write operations.

Attacks that replay valid traffic patterns, use observed function codes, target writable addresses, and stay within the observed value range evade all of these detection classes. The detection problem then shifts to process outcome monitoring: did the physical process behave differently than expected? This requires domain expertise and sensor data that most security monitoring programmes do not have access to.

## The detection gap

The gap between a valid-looking protocol command and a detectable process deviation can be hours or days in slow processes like water treatment, chemical synthesis, or metallurgical operations. The attacker who understands the process timeline can act and withdraw long before any anomaly is visible. Detection at this level requires integrating process historian data with security monitoring, which most organisations have not done.
