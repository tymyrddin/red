# IPsec identity spoofing attacks

## Attack pattern

Identity spoofing attacks target the authentication mechanisms that IPsec uses to establish trust between peers. By forging or manipulating identity information during the IKE negotiation phase, attackers can impersonate legitimate peers, gain unauthorized access to VPN tunnels, or intercept sensitive communications. These attacks exploit weaknesses in how identities are verified, validated, and trusted within the IPsec framework.

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

## Mitigation

### Certificate identity validation
-   Action: Implement strong certificate validation and identity binding
-   How:
    -   Enforce certificate pinning for critical peers
    -   Implement strict certificate path validation
    -   Use OCSP stapling for real-time revocation checking
    -   Bind certificates to specific IP addresses or network ranges
-   Configuration example (Strict certificate validation, cisco):

```text
crypto pki trustpoint VPN-TRUSTPOINT
 enrollment terminal
 revocation-check ocsp
 ocsp url http://ocsp.example.com
 rsakeypair VPN-KEYS 2048
 exit
!
crypto pki certificate chain VPN-TRUSTPOINT
 certificate ca 01
 3082020A 30820192 A0030201 02020101 300D0609 2A864886 F70D0101 05050030 
 ...
  quit
```

### PSK identity protection
-   Action: Secure pre-shared key identity management
-   How:
    -   Use complex, unique identities for each peer
    -   Avoid meaningful or predictable identity strings
    -   Implement identity rate limiting and lockout policies
    -   Regularly rotate PSK identities and keys
-   Configuration example (PSK identity hardening, junos):

```text
security {
    ike {
        pre-shared-key {
            ascii-text "$9$complex-psk-value"; 
            identity {
                user@example.com;
                peer-address 192.0.2.0/24;
            }
        }
        policy IKE-POLICY {
            pre-shared-key-secret "$9$another-complex-value";
        }
    }
}
```

### IPv6 identity binding
-   Action: Strengthen IPv6 identity verification and validation
-   How:
    -   Implement strict IPv6 address ownership verification
    -   Filter and validate IPv6 extension headers
    -   Use Cryptographically Generated Addresses (CGA) for identity binding
    -   Monitor for anomalous extension header usage
-   Configuration example (IPv6 extension header filtering, cli):

```bash
# IPv6 extension header filtering with ip6tables
ip6tables -A INPUT -m rt --rt-type 0 -j DROP
ip6tables -A INPUT -m hl --hl-eq 0 -j DROP
ip6tables -A INPUT -p ipv6-icmp --icmpv6-type 139 -j DROP
```

### Continuous monitoring and auditing

-   Action: Monitor identity verification and authentication events
-   How:
    -   Log all IKE identity negotiation attempts
    -   Implement alerts for identity verification failures
    -   Regularly audit certificate trust stores
    -   Monitor for anomalous identity patterns
-   Configuration example (IKE identity logging, strongswan):

```text
charon {
    syslog {
        ike = 2
        cfg = 2
    }
    filelog {
        /var/log/ike-identity.log {
            time_format = %b %e %T
            ike_name = yes
            ike_sa = yes
            append = no
            default = 1
        }
    }
}
```

## Key insights from real-world implementations

-   Certificate management complexity: Many organizations struggle with proper certificate lifecycle management, leading to expired or misissued certificates.
-   PSK proliferation: Pre-shared keys are often shared across multiple devices, amplifying the impact of identity theft.
-   IPv6 adoption gaps: Limited IPv6 security expertise leads to misconfigured extension header handling.
-   Identity verification bypass: Some implementations prioritize connectivity over security, allowing weak identity verification.

## Future trends and recommendations

-   Automated identity management: Implement automated certificate deployment and PSK rotation systems.
-   Zero-trust identity verification: Treat all identity assertions as untrusted until multiple factors are verified.
-   Blockchain-based identity: Explore decentralized identity management solutions for peer verification.
-   Machine learning detection: Use AI-based monitoring to detect anomalous identity patterns.

## Conclusion

Identity spoofing attacks represent a fundamental threat to IPsec security by targeting the trust establishment process itself. These attacks can completely bypass cryptographic protections by convincing peers to establish tunnels with impostors. Defence requires robust identity verification mechanisms, strong certificate management, secure PSK practices, and comprehensive monitoring. As identity attacks become more sophisticated, organizations must implement multi-factor authentication, strict identity binding, and continuous verification to maintain trust in their IPsec infrastructure. Regular security assessments should include specific testing for identity spoofing vulnerabilities, and all identity verification failures should be treated as potential security incidents.
