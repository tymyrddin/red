# Attack tree (TCP)

TCP is the transport layer on which most internet services depend. The attack surface is the connection state itself: sequence numbers, timers, authentication gaps, and the parser in the kernel that processes it all.

```text
1. Compromise TCP sessions [OR]

    1.1 Connection hijacking [OR]

        1.1.1 Sequence number exploitation [OR]
            1.1.1.1 Off-path ISN prediction via timestamp leaks
            1.1.1.2 In-window guessing due to poor ISN randomisation

        1.1.2 RST and FIN injection [OR]
            1.1.2.1 Spoof RST packets to tear down active connections
            1.1.2.2 FIN spoofing for covert session termination

    1.2 Session establishment attacks [OR]

        1.2.1 SYN-based resource exhaustion
            1.2.1.1 SYN flood to exhaust the half-open connection table

        1.2.2 Authentication bypass [OR]
            1.2.2.1 Exploit TCP-MD5 weaknesses (brute force, implementation flaws)
            1.2.2.2 Race session establishment before authentication completes
            1.2.2.3 Extract or exploit TCP-AO keys (side-channel, key theft, fallback abuse)

    1.3 Off-path and side-channel attacks [OR]

        1.3.1 Blind in-window injection [OR]
            1.3.1.1 NAT slipstreaming variants to inject through middleboxes
            1.3.1.2 Protocol downgrade to bring target onto exploitable transport

        1.3.2 Side-channel data extraction [OR]
            1.3.2.1 TCP timestamp analysis to infer host state or sequence numbers
            1.3.2.2 Encrypted traffic classification for target identification

2. Transport-layer service disruption [OR]

    2.1 Resource exhaustion [OR]

        2.1.1 SACK-based attacks [OR]
            2.1.1.1 Craft packets with excessive SACK blocks to force disproportionate kernel memory allocation
            2.1.1.2 SACK-based kernel memory corruption (e.g., CVE-2019-11477)

        2.1.2 Amplification and reflection [OR]
            2.1.2.1 TCP middlebox reflection
            2.1.2.2 ACK/PSH flood to consume target processing resources

    2.2 Stateful device bypass [OR]

        2.2.1 Firewall and monitoring evasion [OR]
            2.2.1.1 Fragmentation overlap attacks to bypass stateful inspection
            2.2.1.2 Crafted TCP segmentation evasion past cloud load balancers

        2.2.2 TCP Fast Open exploitation
            2.2.2.1 TFO cache poisoning to bypass security controls or inject packets

        2.2.3 Cloud instance resource exhaustion
            2.2.3.1 Exhaust cloud instance resources hosting network services

    2.3 Keepalive and timer abuse [OR]

        2.3.1 Hold timer attacks
            2.3.1.1 Delay TCP ACKs to expire application-layer keepalive timers

        2.3.2 Persist timer exploitation
            2.3.2.1 Force zero-window conditions to exhaust CPU through timer handling

        2.3.3 Retransmission storm
            2.3.3.1 Induce excessive retransmissions via selective packet loss

3. Cross-protocol exploitation [OR]

    3.1 BGP via TCP weaknesses [OR]

        3.1.1 Router OS TCP stack compromise [AND]
            3.1.1.1 TCP stack RCE via vendor-specific flaws (JunOS, IOS XR)
            3.1.1.2 Persistent BGP route manipulation after OS compromise

        3.1.2 BGP session attacks [OR]
            3.1.2.1 Sequence prediction to inject malicious BGP UPDATE messages
            3.1.2.2 Subvert BGP graceful restart via spoofing or memory exhaustion

        3.1.3 Man-in-the-middle at transport layer [OR]
            3.1.3.1 ARP/DNS spoofing to redirect BGP traffic through attacker position
            3.1.3.2 BGP peering over unencrypted IXP links
            3.1.3.3 Route reflector compromise for iBGP-wide route injection

        3.1.4 Supply chain and infrastructure [OR]
            3.1.4.1 Backdoored router firmware or software images
            3.1.4.2 Compromised network management software
            3.1.4.3 Pre-installed weak TCP-AO keys in vendor equipment

        3.1.5 BGP-layer persistence and evasion [OR]
            3.1.5.1 Time-based hijacking (micro-duration announcements)
            3.1.5.2 Geographic-specific route manipulation
            3.1.5.3 Mimicking legitimate AS-path patterns
            3.1.5.4 Exploitation of RPKI 'unknown' validation state
            3.1.5.5 Leveraging peer conflicts for route ambiguity
            3.1.5.6 Adaptive attack timing based on monitoring gaps

    3.2 Multi-protocol chaining [OR]

        3.2.1 TCP to application-layer attacks [OR]
            3.2.1.1 Session hijacking to inject data into application sessions
            3.2.1.2 Protocol downgrade enabling plaintext session attacks

    3.3 Coordinated multi-vector attacks [OR]

        3.3.1 Chained TCP/BGP exploitation [AND]
            3.3.1.1 Initial access via TCP stack vulnerability
            3.3.1.2 Privilege escalation to BGP process
            3.3.1.3 Persistent route manipulation
            3.3.1.4 TCP-AO key material extraction for future sessions

        3.3.2 Distributed session attacks [OR]
            3.3.2.1 Distributed TCP sequence prediction across multiple sources
            3.3.2.2 Synchronised BGP session reset attacks across multiple peers
            3.3.2.3 Cross-platform exploitation campaigns
```

## Nitty gritty risk table

| Attack Path                                                                             | Technical Complexity | Resources Required | Risk Level | Notes                                                                                              |
|-----------------------------------------------------------------------------------------|----------------------|--------------------|------------|-----------------------------------------------------------------------------------------------------|
| 3.1.1.1 TCP stack RCE via vendor-specific flaws (JunOS, IOS XR)                        | High                 | Medium             | High       | Requires knowledge of specific vendor vulnerabilities; can lead to full device compromise.         |
| 2.1.1.2 SACK-based kernel memory corruption (CVE-2019-11477)                           | High                 | Low                | High       | Exploits known vulnerabilities in TCP SACK processing; can cause RCE or DoS.                       |
| 3.1.1.2 Persistent BGP route manipulation after OS compromise                          | Medium               | Low                | High       | After initial access, modifies BGP settings to manipulate routing.                                  |
| 2.1.1.1 Craft packets with excessive SACK blocks                                       | Medium               | Low                | Medium     | Consumes router resources through crafted SACK packets; can lead to DoS.                           |
| 1.2.1.1 SYN flood to exhaust half-open connection table (BGP peer)                     | Low                  | High               | High       | Floods BGP peers with SYN packets; disrupts session establishment.                                  |
| 2.1.1.2 Trigger kernel crashes through crafted TCP packets                             | High                 | Low                | High       | Sends malformed TCP packets to crash the kernel; causes service disruption.                        |
| 1.2.1.1 SYN flood to exhaust the half-open connection table                            | Low                  | High               | Medium     | Basic DoS attack against BGP session establishment; easily detectable.                              |
| 1.2.2.1 Exploit TCP-MD5 weaknesses                                                     | Medium               | Low                | High       | Weak MD5 keys or implementations can be cracked or bypassed.                                       |
| 1.2.2.2 Race session establishment before authentication completes                     | High                 | Medium             | High       | Hijacks TCP session to avoid MD5 authentication; requires sequence prediction.                     |
| 1.1.1 Sequence number exploitation (ISN prediction)                                    | High                 | Low                | High       | Predicts sequence numbers to inject malicious packets; off-path or in-window.                      |
| 3.1.2.1 Sequence prediction to inject malicious BGP UPDATE messages                    | Medium               | Low                | Very High  | Injects fraudulent routes, AS_PATH manipulations, or route flaps to disrupt routing.               |
| 1.1.2.1 Spoof RST packets to tear down active sessions                                 | Medium               | Low                | High       | Injects RST packets or exploits timeouts to drop BGP sessions.                                      |
| 3.1.2.2 Subvert BGP graceful restart                                                   | High                 | Low                | High       | Spoofs graceful restart or exhausts memory during recovery to cause prolonged outages.              |
| 3.1.3.1 ARP/DNS spoofing to redirect BGP traffic                                       | Medium               | Low                | High       | Redirects BGP traffic to attacker-in-the-middle; requires local network access.                    |
| 3.1.3.2 BGP peering over unencrypted IXP links                                         | Low                  | Low                | High       | Eavesdrops on unencrypted BGP sessions at exchange points; easy interception.                       |
| 3.1.3 On-path position for BGP packet capture                                          | High                 | Medium             | Very High  | Attacker positioned on network path can capture and manipulate BGP traffic.                         |
| 3.1.3 Decrypt or modify BGP messages                                                   | Very High            | High               | Very High  | Decrypts BGP messages if encryption is weak or compromised; alters routing updates.                |
| 1.2.2.1 Downgrade TCP-MD5 to plaintext                                                 | Medium               | Low                | High       | Forces fallback to unencrypted sessions if misconfigured.                                            |
| 1.2.2.3 Extract or exploit TCP-AO keys (missing configuration)                         | Medium               | Low                | High       | Targets sessions without TCP-AO authentication; easier to manipulate.                               |
| 1.2.2.3 Bypass TCP-AO protection                                                       | Very High            | High               | Very High  | Extracts keys, exploits crypto weaknesses, or implementation flaws to bypass TCP-AO.               |
| 1.1.1.1 Off-path ISN prediction via timestamp leaks                                    | High                 | Low                | High       | Predicts TCP sequence numbers without being on-path; requires timing or leaks.                     |
| 1.1.2.1 RST/FIN spoofing to disrupt connections                                        | Medium               | Low                | Medium     | Injects RST or FIN packets to disrupt connections; can be used against BGP sessions.                |
| 2.1.2.1 TCP middlebox reflection                                                       | High                 | Medium             | High       | Uses middleboxes to reflect and amplify TCP traffic; can target BGP peers.                         |
| 2.1.2.2 ACK/PSH flood to consume processing resources                                  | Medium               | High               | Medium     | Floods with ACK or PSH packets to consume resources; may impact BGP performance.                   |
| 3.1.2 BGP update reflection/amplification                                              | High                 | Medium             | High       | Reflects and amplifies BGP updates to overwhelm peers or fabricate routes.                          |
| 1.3.1.1 NAT slipstreaming variants                                                     | High                 | Low                | High       | Exploits NAT devices to inject packets; can be used to manipulate BGP sessions.                    |
| 1.3.1.2 Protocol downgrade attacks                                                     | High                 | Low                | Medium     | Forces downgrade to TCP to exploit vulnerabilities; less common for BGP.                            |
| 1.3.2.1 TCP timestamp analysis                                                         | Medium               | Low                | Medium     | Analyses timestamps to infer information about hosts or networks.                                   |
| 1.3.2 Application data correlation                                                     | High                 | Low                | Medium     | Correlates TCP data with BGP applications to identify vulnerabilities.                              |
| 1.3.2.2 Encrypted traffic classification for target identification                     | High                 | Medium             | Medium     | Uses traffic analysis to classify encrypted BGP sessions; reconnaissance for further attacks.       |
| 2.2.1.2 Crafted TCP segmentation evasion past cloud load balancers                     | High                 | Low                | High       | Evades cloud load balancers using TCP segmentation tricks; can target BGP speakers.                |
| 2.2.3.1 Cloud instance resource exhaustion                                             | Medium               | High               | High       | Exhausts resources of cloud instances hosting BGP; causes DoS.                                      |
| 2.2.2.1 TCP Fast Open cache poisoning                                                  | High                 | Low                | High       | Poisons TFO caches to bypass security or inject packets into BGP sessions.                         |
| 2.2.1.1 Fragmentation overlap attacks                                                  | High                 | Low                | High       | Uses overlapping fragments to evade firewalls or IDS; can target BGP.                               |
| 2.2.1 Evasion of BGP monitoring systems                                                | High                 | Low                | High       | Uses TCP-layer evasion techniques to avoid detection by BGP monitoring tools.                       |
| 3.1.1.1 TCP stack vulnerability exploitation for BGP compromise                        | High                 | Medium             | High       | Combines TCP exploits with BGP manipulation for persistent access.                                  |
| 3.1.1.2 Persistent BGP route manipulation post-OS compromise                           | Medium               | Low                | Very High  | After compromising OS, modifies BGP routes for long-term control.                                   |
| 2.1.1.2 Memory corruption via crafted TCP options                                      | Very High            | Low                | High       | Uses TCP options to corrupt memory and compromise BGP processes.                                     |
| 2.1.1 Resource exhaustion via TCP                                                      | Medium               | High               | High       | Exhausts kernel resources to disrupt BGP operations.                                                 |
| 3.1.1 BGP process isolation bypass                                                     | High                 | Low                | High       | Escapes process isolation to manipulate BGP directly from kernel.                                   |
| 1.2.2.1 TCP-MD5 hash cracking (weak keys)                                              | Medium               | Low                | High       | Cracks weak MD5 keys used in BGP authentication.                                                    |
| 1.2.2.3 TCP-AO hash collision attacks                                                  | Very High            | High               | Very High  | Exploits hash collisions in TCP-AO to bypass authentication.                                        |
| 3.1.4.1 RPKI certificate chain exploitation                                            | High                 | Medium             | High       | Compromises RPKI certificates to validate fraudulent BGP routes.                                    |
| 1.2.2.3 TCP-AO key compromise through side-channels                                    | Very High            | High               | Very High  | Uses side-channels to extract TCP-AO keys from compromised routers.                                |
| 1.2.2.3 Algorithm vulnerability exploitation (SHA-1/256 in TCP security)               | Very High            | High               | Very High  | Exploits weaknesses in SHA-1 or SHA-256 used in BGP session security.                              |
| 1.2.2.1 Force plaintext BGP sessions                                                   | Medium               | Low                | High       | Downgrades sessions to plaintext to eavesdrop or manipulate.                                        |
| 1.2.2.3 Exploit absent authentication on BGP sessions                                  | Low                  | Low                | Medium     | Targets BGP sessions with no authentication; easy to manipulate.                                    |
| 1.2.2.2 Session negotiation manipulation                                               | High                 | Low                | High       | Manipulates session setup to weaken security or force vulnerabilities.                              |
| 1.2.2.3 TCP-AO fallback mechanism exploitation                                         | High                 | Low                | High       | Exploits fallback mechanisms to bypass TCP-AO authentication.                                       |
| 3.1.3.3 Compromised IXP route server software                                          | High                 | Medium             | Very High  | Compromises software at IXPs to manipulate routing for multiple networks.                           |
| 3.1.3.2 BGP peering link interception at IXP                                           | High                 | Medium             | Very High  | Intercepts peering links at IXPs to manipulate or eavesdrop on BGP.                                |
| 3.1.3.3 Route reflector compromise                                                     | High                 | Medium             | Very High  | Compromises route reflectors to inject malicious routes into large networks.                        |
| 3.1.4.2 Exposed BGP monitoring systems                                                 | Low                  | Low                | Medium     | Accesses exposed monitoring systems to gather intelligence or disrupt operations.                   |
| 3.3.1.2 Privilege escalation to BGP process (via stolen SSH keys)                      | Medium               | Low                | High       | Uses stolen SSH keys to access and manipulate BGP routers.                                          |
| 3.1.4.2 Default credentials on admin interfaces                                        | Low                  | Low                | High       | Uses default credentials to gain access to router management interfaces.                            |
| 1.2.2.3 TCP-AO key material theft through configuration leaks                          | Medium               | Low                | High       | Steals TCP-AO keys from leaked configuration files or backups.                                      |
| 3.1.5.1 Time-based hijacking (short-lived route announcements)                         | High                 | Low                | High       | Announces fraudulent routes for short periods to avoid detection.                                   |
| 3.1.5.2 Geographic-specific route manipulation                                         | High                 | Low                | High       | Targets specific regions with route manipulations to localise impact.                               |
| 3.1.5.3 Mimicking legitimate AS-path patterns                                          | High                 | Low                | High       | Copies legitimate AS-paths to make fraudulent routes appear valid.                                  |
| 3.1.5.4 RPKI 'unknown' state exploitation                                              | Medium               | Low                | Medium     | Exploits routes with unknown RPKI validation status to bypass checks.                               |
| 3.1.5.5 Leveraging peer conflicts for route ambiguity                                  | High                 | Low                | High       | Creates conflicting route advertisements to confuse networks and evade detection.                   |
| 3.1.5.6 Adaptive attack timing based on monitoring gaps                                | Very High            | Low                | Very High  | Times attacks to avoid monitoring periods or response teams.                                        |
| 3.3.1.1 Initial access via TCP stack vulnerability                                     | High                 | Medium             | High       | Uses TCP vulnerabilities to gain initial access to BGP routers.                                     |
| 3.3.1.2 Privilege escalation to BGP process                                            | High                 | Low                | High       | Escalates privileges to manipulate BGP processes directly.                                          |
| 3.3.1.3 Persistent route manipulation                                                  | Medium               | Low                | Very High  | Modifies BGP routes for long-term control or traffic diversion.                                     |
| 3.3.1.4 TCP-AO key material extraction                                                 | Very High            | High               | Very High  | Extracts TCP-AO keys for future authentication bypass or session hijacking.                         |
| 3.3.2.1 Distributed TCP sequence prediction                                            | Very High            | High               | Very High  | Coordinates multiple sources to predict TCP sequences for BGP session hijacking.                    |
| 3.3.2.2 Synchronised BGP session reset attacks                                         | High                 | Medium             | High       | Coordinates resets of multiple BGP sessions to cause widespread routing instability.                |
| 3.3.2.3 Cross-platform exploitation campaigns                                          | Very High            | High               | Very High  | Targets multiple router platforms and BGP implementations for maximum impact.                       |
| 3.1.4.1 Backdoored router firmware or software images                                  | High                 | High               | Very High  | Compromises firmware or images to introduce backdoors into BGP routers.                             |
| 3.1.4.2 Compromised network management software                                        | High                 | Medium             | High       | Compromises software used to manage BGP networks for unauthorised access.                           |
| 3.1.4.3 Pre-installed weak TCP-AO keys in vendor equipment                             | Medium               | Low                | High       | Uses weak default keys installed by vendors to compromise BGP authentication.                       |
