# Protocol downgrade attacks

## Attack Pattern

IPsec protocol downgrade attacks exploit the backward compatibility and negotiation mechanisms inherent in the protocol suite to force connections to use weaker security parameters or obsolete protocol versions. By manipulating the initial handshake or negotiation process, attackers can undermine the security of established tunnels, often without either endpoint being aware of the degradation. These attacks are particularly effective because they target the trust-based negotiation process before cryptographic protection is fully established.

```text
1. Version downgrade attacks [OR]

    1.1 IKEv2 to IKEv1 downgrade [OR]

        1.1.1 Forged IKE_SA_INIT response [AND]
            1.1.1.1 Suggest IKEv1 fallback
            1.1.1.2 Exploit victim preference for backward compatibility [AND]
                1.1.1.2.1 Initiate connection using legacy IKEv1 parameters
                1.1.1.2.2 Force weaker cryptographic negotiation

        1.1.2 Man-in-the-middle blocking of IKEv2 packets [AND]
            1.1.2.1 Intercept and drop IKEv2 messages
            1.1.2.2 Force timeout handling [AND]
                1.1.2.2.1 Trigger fallback mechanisms to IKEv1
                1.1.2.2.2 Exploit default configuration behaviours

        1.1.3 Resource exhaustion on IKEv2 stack [AND]
            1.1.3.1 Flood IKEv2 negotiation messages
            1.1.3.2 Trigger server-side degradation [AND]
                1.1.3.2.1 Force slower processing
                1.1.3.2.2 Encourage fallback to legacy mode

        1.1.4 Spoofed error messages indicating IKEv2 incompatibility [AND]
            1.1.4.1 Craft notifications mimicking IKEv2 errors
            1.1.4.2 Induce fallback behaviour [AND]
                1.1.4.2.1 Victim selects IKEv1 automatically
                1.1.4.2.2 Exploit known IKEv1 weaknesses

    1.2 ESP to AH protocol forcing [OR]

        1.2.1 Negotiation manipulation [AND]
            1.2.1.1 Advertise AH only
            1.2.1.2 Exploit victim policy favouring authentication over encryption [AND]
                1.2.1.2.1 Force removal of ESP from negotiation
                1.2.1.2.2 Reduce confidentiality guarantees

        1.2.2 Forged capability advertisements [AND]
            1.2.2.1 Remove ESP support from advertised capabilities
            1.2.2.2 Exploit victim’s algorithm selection [AND]
                1.2.2.2.1 Victim chooses AH exclusively
                1.2.2.2.2 Enable weaker protection than intended

        1.2.3 Resource exhaustion attacks on ESP implementation [AND]
            1.2.3.1 Send malformed or high-volume ESP traffic
            1.2.3.2 Trigger processing delays or crashes [AND]
                1.2.3.2.1 Victim switches to AH for operational continuity
                1.2.3.2.2 Attacker exploits reduced security

        1.2.4 Policy manipulation [AND]
            1.2.4.1 Adjust policy to favour AH for “compatibility”
            1.2.4.2 Force weaker protection on victim network [AND]
                1.2.4.2.1 Exploit administrative defaults
                1.2.4.2.2 Maintain operational connectivity while reducing confidentiality

    1.3 Strong-to-weak algorithm negotiation [OR]

        1.3.1 Algorithm list reordering [AND]
            1.3.1.1 Prioritise weak ciphers in negotiation
            1.3.1.2 Exploit victim’s automatic selection logic [AND]
                1.3.1.2.1 Victim selects first acceptable cipher
                1.3.1.2.2 Attacker gains weaker cryptographic strength

        1.3.2 Selective packet drop [AND]
            1.3.2.1 Drop packets negotiating strong algorithms
            1.3.2.2 Force fallback to weak algorithms [AND]
                1.3.2.2.1 Exploit timeout/failure handling
                1.3.2.2.2 Induce weaker session keys

        1.3.3 Spoofed error messages [AND]
            1.3.3.1 Claim strong algorithm negotiation failure
            1.3.3.2 Victim negotiates weaker algorithms [AND]
                1.3.3.2.1 Exploit automatic error handling
                1.3.3.2.2 Reduce effective security margin

        1.3.4 Forged Notify payloads [AND]
            1.3.4.1 Indicate algorithm incompatibility
            1.3.4.2 Force victim selection of weak cipher [AND]
                1.3.4.2.1 Exploit protocol compliance with RFC 7296
                1.3.4.2.2 Achieve downgrade without direct key compromise
```

## Why it works

-   Backward compatibility requirements: Enterprises often maintain support for legacy protocols and algorithms to ensure interoperability with older systems.
-   Negotiation transparency: The algorithm and version negotiation process occurs before cryptographic protection is established, making it vulnerable to manipulation.
-   Error handling complexity: Sophisticated error handling and fallback mechanisms can be exploited to trigger downgrades.
-   Configuration complexity: The numerous IPsec configuration options make it difficult to maintain consistent security policies across all endpoints.
-   Silent degradation: Many systems fail to log or alert on protocol downgrades, allowing attacks to go undetected.
-   Interoperability testing gaps: Security testing often focuses on established tunnels rather than the negotiation phase.
-   Protocol fallback: Attackers can trick an IKEv2 peer into falling back to IKEv1 by forging IKE_SA_INIT responses, exploiting the victim’s preference for backward compatibility.
-   Packet interference: Dropping or delaying IKEv2 messages can force timeouts, making the victim automatically attempt legacy negotiation.
-   Resource exhaustion: Flooding the IKEv2 stack with messages can slow or destabilise it, encouraging fallback to older versions or weaker modes.
-   Spoofed error signalling: Attackers can send crafted error notifications indicating IKEv2 failure, prompting the victim to negotiate IKEv1 instead.
-   ESP→AH forcing: By manipulating negotiation, excluding ESP capabilities, or exploiting administrative policy defaults, attackers can force the victim to use AH-only tunnels, reducing confidentiality.
-   Algorithm list manipulation: Reordering supported ciphers in proposals can prioritise weak algorithms, relying on victims to pick the first acceptable option.
-   Selective packet drops: By selectively dropping packets negotiating strong algorithms, attackers can coerce a fallback to weaker cryptography.
-   Forged Notify payloads: Maliciously crafted notifications can indicate algorithm incompatibility, nudging the peer to choose weaker cryptographic primitives.
-   Compatibility-driven policy abuse: Network or device policies that favour “compatibility” can be exploited to maintain connectivity while silently reducing security.
