# Identity spoofing attacks

## Attack pattern

Identity spoofing attacks target the authentication mechanisms that IPsec uses to establish trust between peers. By forging or manipulating identity information during the IKE negotiation phase, attackers can impersonate legitimate peers, gain unauthorised access to VPN tunnels, or intercept sensitive communications. These attacks exploit weaknesses in how identities are verified, validated, and trusted within the IPsec framework.

``` text
1. Identity spoofing [OR]

    1.1 Certificate identity spoofing [OR]

        1.1.1 Rogue certificate issuance [AND]
            1.1.1.1 Compromise CA private key
            1.1.1.2 Issue attacker-controlled certificates [AND]
                1.1.1.2.1 Sign certificates for arbitrary domains or peers
                1.1.1.2.2 Bypass victim trust checks

        1.1.2 Common Name (CN) spoofing [AND]
            1.1.2.1 Craft certificate CN to match target peer
            1.1.2.2 Use in TLS/IKE/IPsec handshake [AND]
                1.1.2.2.1 Victim accepts spoofed peer identity
                1.1.2.2.2 Enable man-in-the-middle or impersonation

        1.1.3 Subject Alternative Name (SAN) manipulation [AND]
            1.1.3.1 Insert attacker-controlled SAN entries
            1.1.3.2 Exploit victim certificate validation [AND]
                1.1.3.2.1 Match additional hostnames/IPs
                1.1.3.2.2 Facilitate multi-target impersonation

        1.1.4 Certificate validity period extension [AND]
            1.1.4.1 Exploit clock skew in victim system
            1.1.4.2 Present expired or future-dated certificate [AND]
                1.1.4.2.1 Bypass time-based certificate checks
                1.1.4.2.2 Extend window for impersonation attacks

        1.1.5 Intermediate CA injection [AND]
            1.1.5.1 Insert malicious intermediate CA into trust chain
            1.1.5.2 Sign certificates for arbitrary identities [AND]
                1.1.5.2.1 Exploit victim trust model
                1.1.5.2.2 Enable wide-scale spoofing without root compromise

    1.2 PSK identity manipulation [OR]

        1.2.1 Identity field tampering [AND]
            1.2.1.1 Modify IKE identity payloads
            1.2.1.2 Impersonate legitimate peer [AND]
                1.2.1.2.1 Exploit weak validation of peer ID
                1.2.1.2.2 Gain session establishment privileges

        1.2.2 PSK hash cracking [AND]
            1.2.2.1 Capture PSK handshake messages
            1.2.2.2 Compute pre-shared key from hashes [AND]
                1.2.2.2.1 Use brute force or dictionary attacks
                1.2.2.2.2 Recover PSK to impersonate peer

        1.2.3 Identity reflection attacks [AND]
            1.2.3.1 Exploit Aggressive Mode symmetry
            1.2.3.2 Reflect identity payloads back to victim [AND]
                1.2.3.2.1 Bypass authentication checks
                1.2.3.2.2 Facilitate man-in-the-middle

        1.2.4 Peer database enumeration [AND]
            1.2.4.1 Guess or probe identity fields
            1.2.4.2 Discover configured peers [AND]
                1.2.4.2.1 Use systematic trial identities
                1.2.4.2.2 Map victim configuration for targeted attacks

    1.3 IPv6 extension header identity abuse [OR]

        1.3.1 Routing header manipulation [AND]
            1.3.1.1 Craft IPv6 routing headers
            1.3.1.2 Spoof source addresses [AND]
                1.3.1.2.1 Bypass source-based identity checks
                1.3.1.2.2 Position attacker in MITM path

        1.3.2 Hop-by-hop option attacks [AND]
            1.3.2.1 Insert attacker-controlled hop options
            1.3.2.2 Evade identity verification [AND]
                1.3.2.2.1 Skip or confuse processing nodes
                1.3.2.2.2 Achieve stealthy traffic interception

        1.3.3 Destination option header spoofing [AND]
            1.3.3.1 Craft destination options to mislead peers
            1.3.3.2 Impersonate intended destination [AND]
                1.3.3.2.1 Enable targeted MITM attacks
                1.3.3.2.2 Exploit weak header validation

        1.3.4 Fragment header attacks [AND]
            1.3.4.1 Fragment IPv6 packets to bypass inspection
            1.3.4.2 Conceal spoofed identity [AND]
                1.3.4.2.1 Evade deep packet inspection
                1.3.4.2.2 Maintain session-level impersonation
```

## Why it works

-   Trust model complexity: PKI hierarchies and trust relationships create multiple attack vectors for identity spoofing.
-   Weak identity binding: Many implementations don't properly bind cryptographic identities to network identities.
-   Protocol flexibility: IKE's support for multiple identity types and formats increases the attack surface.
-   IPv6 complexity: Extension headers provide additional mechanisms for obfuscating true identities.
-   Configuration errors: Misconfigured certificate policies and weak PSK management are common.
-   Monitoring gaps: Identity verification failures often lack proper logging and alerting.

## Counter moves

Identity spoofing attacks is what this page works through. Strong IKE configuration and pruning weak proposals are the fix. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
