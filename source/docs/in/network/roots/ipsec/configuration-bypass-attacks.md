# Configuration bypass attacks

## Attack pattern

Configuration bypass attacks exploit weaknesses in how IPsec policies are defined, enforced, and processed. By manipulating policy enforcement mechanisms or exploiting ambiguities in policy application, attackers can bypass intended security controls, evade traffic protection, or gain unauthorised access to network resources. These attacks target the policy decision points that determine which traffic receives IPsec protection and how that protection is applied.

```text
2.1.3 Configuration Bypass [OR]

    2.1.3.1 Bypass SPD (Security Policy Database) rules
        • Crafted packet manipulation to evade policy matching
        • IP fragmentation to split policy-relevant information across packets
        • Traffic flow manipulation to fall between policy definitions
        • Protocol field spoofing to match unintended policies

    2.1.3.2 Weak policy enforcement
        • Fail-open behavior exploitation during system stress
        • Policy cache poisoning through timing attacks
        • Race conditions in policy application during rekeying
        • Boundary condition exploitation in policy scope matching

    2.1.3.3 Mixed mode policy exploitation
        • Policy ambiguity exploitation in transport vs tunnel mode
        • Simultaneous protected and unprotected session manipulation
        • Policy priority manipulation to select weaker protections
        • Mode transition attacks during session establishment

    2.1.3.4 Default configuration abuse
        • Vendor default policy and key exploitation
        • Default permit policies in security gateway configurations
        • Hardcoded credential and policy exploitation
        • Out-of-box configuration vulnerability exploitation
```

## Why it works

-   Policy complexity: SPD rules can be complex and difficult to manage consistently.
-   Performance optimisation: Policy lookup optimisations may create bypass opportunities.
-   Implementation variance: Different vendors implement policy enforcement differently.
-   Legacy support: Backward compatibility requirements maintain vulnerable configurations.
-   Human error: Complex policy configurations are prone to misconfiguration.
-   Documentation gaps: Default configurations often lack security-focused documentation.

## Counter moves

Configuration bypass attacks is the case here. Strong IKE configuration and pruning weak proposals are the fix. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
