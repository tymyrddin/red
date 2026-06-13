# CDN fronting

CDN fronting puts a high-reputation edge between the target and the redirector. The TLS SNI points at a trusted
hostname served by the CDN; the inner Host header points at the operator's domain. The CDN routes by Host, the
network observer sees the SNI.

Most major providers disabled classic domain fronting around 2018: AWS CloudFront, Google, and Microsoft Azure all
enforce SNI and Host alignment. A handful still permit it under specific configurations, and others allow domain
hiding via Encrypted Client Hello (ECH) where the SNI is encrypted entirely.

## Practical options in 2026

* Cloudflare Workers and Cloudflare Pages: an operator-controlled worker on a free Cloudflare zone can act as the
entry point. The TLS SNI is `*.workers.dev` or the zone's apex; the worker forwards to the redirector. Not classic
fronting, but a reputational benefit.
* Fastly: similar pattern with Compute@Edge.
* ECH-enabled CDNs: where both client and CDN support ECH, the SNI itself is encrypted, removing the need for
fronting.
* Azure Front Door, AWS CloudFront: only useful if the operator controls a tenant in those clouds, which conflicts
with the rest of this section's [opsec posture](../bouncers/providers.md).

## Cloudflare Worker forwarder

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = "redirector.<otherdomain>.com";
    return fetch(url, request);
  }
};
```

Deploy under a free workers.dev hostname. The implant beacons to `https://<name>.workers.dev/...`, the worker
forwards to the redirector.

## Trade-offs

* The CDN can see plaintext bytes after TLS termination. Treat the CDN operator as a logging adversary.
* Free tiers have request quotas. Burn a fresh account per operation.
* Account creation usually wants a credit card or phone number, which conflicts with the
[anonymous payments](../bouncers/payments.md) approach unless using prepaid or single-use details.
