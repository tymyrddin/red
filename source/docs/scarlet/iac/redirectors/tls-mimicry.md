# TLS mimicry

A redirector can hide its IP, rotate its domain, and serve a flawless cover site, and still announce itself the
moment it opens a TLS connection. The ClientHello is a confession. The order of cipher suites, the extension list,
the supported curves, the ALPN values: all of it is set by whatever TLS library the tooling was built on, and most
tooling was not built on a browser.

## JA3, JA4, and JARM

JA3 hashes a handful of ClientHello fields into a single fingerprint. For years it was the cheap way to say "this
TLS handshake came from a Go binary, not Chrome". JA4 is the newer scheme: more fields, a structured rather than
hashed form, and harder to collide by accident. Both describe the client side of the handshake.

JARM is the mirror image. A defender actively probes a suspected redirector and fingerprints how its TLS responder
behaves. A self-hosted C2 listener answering with a default JARM that matches a known framework is a gift, even
through a redirector, if the redirector passes TLS through rather than terminating it.

The failure mode is rarely the fingerprint alone. It is the mismatch. A handshake that fingerprints as a Go
client carrying a `User-Agent` that claims to be Chrome on Windows is the kind of contradiction that behavioural
detection is built to notice. Consistency across the layers is the point, not any single value.

## Borrowing a real client's hello

The usual approach is to stop hand-rolling the handshake and borrow one from a real browser. The
[uTLS](https://github.com/refraction-networking/utls) library exposes preset ClientHello identities, so a Go
implant or redirector can present Chrome's handshake instead of Go's:

```go
import tls "github.com/refraction-networking/utls"

conn := tls.UClient(rawConn, &tls.Config{ServerName: host}, tls.HelloChrome_Auto)
if err := conn.Handshake(); err != nil {
    // fall back, rotate, or fail closed
}
```

`curl-impersonate` does the same trick for shell-based tooling, shipping builds that reproduce specific browser
handshakes end to end. The `User-Agent` then needs to match the identity the handshake claims, or the work is
wasted.

## Trade-offs

* A borrowed hello ages. `HelloChrome_Auto` tracking a 2024 Chrome in 2026 is itself an anomaly, because real
estates have moved on. The fingerprint that hides best is the one most of the target's own traffic is using this
month, which means revisiting the preset as browsers ship.
* Encrypted Client Hello changes the terrain. Where the client and the CDN both support ECH, the SNI and much of
the hello are encrypted, which removes some of what JA3 reads. That overlaps with the ECH note in
[CDN fronting](cdn-fronting.md), and it is not yet universal.
* Mimicry buys the handshake, not the behaviour. Matching Chrome's hello while beaconing on a fixed 60-second
interval to a single host leaves the timing and volume tells untouched. The handshake is one layer.

## What the defender does with it

Fingerprinting is cheap to run at the egress and cheap to correlate. The patterns worth assuming are on the other
side: pairing the TLS fingerprint against the stated `User-Agent`, flagging fingerprints that no installed browser
in the estate produces, and JARM-scanning infrastructure that turns up in other telemetry. None of these reads the
payload. They read the shape of the conversation, which is why a redirector that only hides the address tends to
surface anyway.

For the raw byte-shuffling pass-through that keeps the certificate on the frontend, see [socat](socat.md). For the
HTTP-aware hop that can filter on headers before the handshake even matters, see
[nginx](nginx-redirector.md).
