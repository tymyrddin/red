# Supply chain compromise

Networking equipment passes through a supply chain that rarely includes cryptographic verification at each transfer point. A compromise inserted during manufacture, distribution, or software development can persist for the operational lifetime of the device.

## Attack tree

```text
1. Supply chain compromise [OR]

    1.1 Backdoored router firmware and images [OR]

        1.1.1 Manufacturer-level firmware compromise
            1.1.1.1 Malicious code insertion during development
            1.1.1.2 Compromise of build systems and compilation environments
            1.1.1.3 Trojanised software updates and security patches
            1.1.1.4 Hidden functionality in official firmware releases

        1.1.2 Distribution channel compromise
            1.1.2.1 Manipulation of firmware download servers
            1.1.2.2 DNS poisoning for update server redirection
            1.1.2.3 Compromise of software repository integrity
            1.1.2.4 Malicious replacement of legitimate firmware images

        1.1.3 Hardware-level backdoor implantation
            1.1.3.1 Malicious modification of bootloader components
            1.1.3.2 Hardware trojan insertion during manufacturing
            1.1.3.3 Compromised management controllers and baseboard systems
            1.1.3.4 Persistent firmware storage manipulation

        1.1.4 Verification mechanism subversion
            1.1.4.1 Compromise of code signing infrastructure
            1.1.4.2 Weak encryption implementation for firmware verification
            1.1.4.3 Bypass of secure boot mechanisms
            1.1.4.4 Manipulation of checksum validation processes

    1.2 Compromised network management software [OR]

        1.2.1 Network management system backdoors
            1.2.1.1 Malicious functionality in network controllers
            1.2.1.2 Compromised orchestration platforms
            1.2.1.3 Trojanised configuration management tools
            1.2.1.4 Backdoored monitoring and analytics systems

        1.2.2 Remote access tool compromise
            1.2.2.1 Malicious features in remote management software
            1.2.2.2 Compromised out-of-band management systems
            1.2.2.3 Backdoored administrative interfaces
            1.2.2.4 Manipulated remote console applications

        1.2.3 Monitoring and visibility system manipulation
            1.2.3.1 Compromised network telemetry collection
            1.2.3.2 Malicious log processing and analysis tools
            1.2.3.3 Backdoored security information systems
            1.2.3.4 Manipulated performance monitoring applications

        1.2.4 Automation tool exploitation
            1.2.4.1 Malicious scripting framework components
            1.2.4.2 Compromised infrastructure-as-code templates
            1.2.4.3 Backdoored deployment automation tools
            1.2.4.4 Manipulated continuous integration systems

    1.3 Pre-installed weak TCP authentication option keys in vendor equipment [OR]

        1.3.1 Weak key generation implementation
            1.3.1.1 Poor entropy sources in key generation
            1.3.1.2 Predictable key material generation algorithms
            1.3.1.3 Insufficient key length and complexity
            1.3.1.4 Repeated key patterns across devices

        1.3.2 Key storage and handling vulnerabilities
            1.3.2.1 Insecure key storage mechanisms
            1.3.2.2 Key material exposure in debug interfaces
            1.3.2.3 Weak key protection during distribution
            1.3.2.4 Compromise of key management systems

        1.3.3 Certificate authority compromise
            1.3.3.1 Rogue certificate issuance for network devices
            1.3.3.2 Compromise of device identity certificates
            1.3.3.3 Manipulation of certificate validation processes
            1.3.3.4 Weak certificate authority implementation

        1.3.4 Default credential and key exploitation
            1.3.4.1 Hardcoded default keys in device firmware
            1.3.4.2 Predictable key derivation from serial numbers
            1.3.4.3 Shared keys across multiple devices
            1.3.4.4 Lack of key rotation enforcement
```

## Why it works

Supply chains involve multiple transfer points, each a potential compromise opportunity. Firmware verification is often nominal: checksums can be forged if signing infrastructure is compromised, and secure boot coverage is inconsistent across vendors and device generations. Networking equipment may remain in service for a decade or more, extending the window for a supply chain implant to generate value. Management software frequently receives less security scrutiny than the equipment it manages.

## Operational implications

- Hardware-level implants survive software updates, factory resets, and CVE remediation cycles.
- Compromised management software may provide persistent access to all devices under its control, multiplying the impact of a single supply chain entry point.
- Pre-installed weak keys on multiple devices from the same vendor batch allow systematic authentication bypass across a fleet.

## Detection pressures

- Firmware hashes that do not match published vendor digests indicate modification, though verification requires tooling that many operators do not have deployed.
- Unexpected outbound connections from management software or routers to external addresses may surface in firewall or DNS logs.
- Debug interfaces exposing key material may be detectable through port scanning if devices face a monitored segment.

## Related

- [Advanced persistence mechanisms](advanced-persistence-mechanisms.md)
- [Rootways: BGP attack tree](../bgp/tree.md)
