# TLS and encrypted channel attacks

TLS is the dominant transport security mechanism and the primary reason that passive network capture no longer yields application-layer credentials as readily as it did before 2015. The attacks against TLS are therefore not primarily cryptographic but architectural: they target the validation of certificates, the downgrade negotiation, and the implementation quality of the TLS stack itself. The goal is usually not to break the encryption but to replace it, interposing a controlled endpoint between the client and server.

## TLS interception

TLS inspection devices, whether deployed as security controls or as attack infrastructure, operate by terminating the client's TLS session at the intercepting device, inspecting or modifying the decrypted traffic, then re-encrypting it in a new TLS session to the original server. The client must trust the intercepting device's CA certificate for this to succeed without a warning.

In enterprise environments, a corporate root CA is often installed in the operating system's trust store via Group Policy. This allows network inspection appliances to present certificates for arbitrary destinations signed by the corporate CA. An attacker who obtains this CA private key can issue certificates for any domain. The key is typically stored on a hardware appliance, but backup files and configuration exports are sometimes less well protected.

## SSL stripping

SSL stripping attacks target the transition from HTTP to HTTPS rather than HTTPS itself. When a user navigates to `http://example.com`, a server that wants to enforce HTTPS responds with a redirect to `https://example.com`. An attacker positioned between the client and server can intercept the initial HTTP request, maintain an HTTPS connection to the server, and present an HTTP connection to the client. The client never sees TLS and never receives the redirect.

```bash
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

HSTS defeats SSL stripping for domains that have been visited before: the browser refuses to make non-HTTPS connections to any domain in its HSTS cache. HSTS preloading extends this to domains that have never been visited, provided they appear in the browser's built-in preload list. Stripping attacks therefore work primarily against first-time visits to non-preloaded domains, which still represents a large proportion of real-world traffic.

## Certificate validation failures

The chain of trust in TLS depends on every link being validated correctly. Common failure modes include:

Wildcard certificate scope is checked incorrectly by some clients: `*.example.com` matches `sub.example.com` but should not match `sub.sub.example.com` or `example.com` itself, and some implementations have historically accepted these incorrectly.

Self-signed certificate acceptance is configured explicitly in some applications and scripts. Command-line tools and automation scripts frequently include flags such as `-k` or `--insecure` to skip certificate validation, and these flags sometimes persist into production use.

Certificate pinning implementations that check the wrong value, pin an intermediate CA rather than the leaf certificate, or implement the comparison in a way that can be bypassed are common in mobile applications. Tools such as Frida can hook certificate validation functions at runtime and return success regardless of the actual certificate.

## Legacy protocol downgrade

TLS version negotiation allows a client and server to agree on the highest mutually supported version. Downgrade attacks manipulate this negotiation, causing the connection to use an older and weaker version. POODLE demonstrated that SSLv3 could be forced by simulating handshake failures until the client fell back; BEAST required TLS 1.0's CBC mode. Both SSLv3 and TLS 1.0 should be disabled on any current server, and their absence can be confirmed with `testssl.sh` or `nmap --script ssl-enum-ciphers`.

The FREAK and Logjam attacks targeted export-grade cryptography that remained in some TLS stacks as legacy code. These are largely historical issues in current software, but they remain relevant against embedded devices, appliances, and any system that has not received firmware updates.
