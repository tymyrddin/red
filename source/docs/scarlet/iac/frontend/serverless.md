# Serverless frontends

The [nginx setup](nginx.md) runs on a VPS: a host that can be seized, imaged, and subpoenaed. A serverless
frontend moves the routing logic into managed compute with no persistent disk, no long-lived process, and no box
to hand over. When the function returns, the execution environment evaporates. The TLS endpoint is a cloud
provider hostname, which carries that provider's reputation rather than a fresh VPS with none.

The cost is identity. Lambda and Cloud Run tie the account to a real billing identity, which puts them in the
same category as the [identity-bound providers](../bouncers/providers.md) to avoid for target-facing
infrastructure. Where the engagement scope tolerates that linkage, or where the serverless layer sits on the
management side only, the operational conveniences are real.

## Lambda as a reverse proxy

AWS API Gateway with a Lambda behind it gives an HTTPS endpoint at a `*.execute-api.<region>.amazonaws.com`
hostname, with a managed certificate and no server to patch. The function receives the API Gateway event and
forwards it upstream.

```python
import json, urllib.request, urllib.error

UPSTREAM = "https://frontend.<otherdomain>.com"

def handler(event, context):
    method  = event.get("httpMethod", "GET")
    path    = event.get("path", "/")
    headers = event.get("headers") or {}
    body    = event.get("body") or ""

    req = urllib.request.Request(
        UPSTREAM + path,
        data=body.encode() if body else None,
        headers={k: v for k, v in headers.items()
                 if k.lower() not in ("host", "x-forwarded-for")},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {
                "statusCode": resp.status,
                "headers": dict(resp.headers),
                "body": resp.read().decode(errors="replace"),
            }
    except urllib.error.HTTPError as e:
        return {"statusCode": e.code, "headers": {}, "body": ""}
```

Deploy under a custom domain mapped through API Gateway if the `execute-api` hostname is too recognisable for
the engagement. The [masquerading](masquerading.md) rules still apply: the domain the target sees determines
the category verdict.

## GCP Cloud Run

Cloud Run serves a container behind a managed HTTPS endpoint at `*.run.app`. A minimal Go container that
reverse-proxies upstream fits in a few dozen megabytes and starts cold in under a second:

```go
package main

import (
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
)

func main() {
    upstream, _ := url.Parse(os.Getenv("UPSTREAM"))
    proxy := httputil.NewSingleHostReverseProxy(upstream)
    proxy.Director = func(req *http.Request) {
        req.URL.Scheme = upstream.Scheme
        req.URL.Host   = upstream.Host
        req.Host       = upstream.Host
    }
    http.ListenAndServe(":"+os.Getenv("PORT"), proxy)
}
```

Set `UPSTREAM` to the actual [backend](../backends/c2s.md) or next-hop nginx. Cloud Run scales to zero between
requests, so there is nothing running between beacon intervals.

## Trade-offs

* The provider logs every invocation with timestamp, source IP, and payload size. The execution environment
evaporates; the log does not.
* Cold starts add latency. A function that has not run recently takes a second or two to respond, which a
C2 beacon profile with tight timeout values may read as a dead channel and rotate away from.
* Custom domains on API Gateway and Cloud Run require DNS records, which ties back to the
[domain opsec](masquerading.md) question.
* Serverless functions are trivially torn down and redeployed under a new URL, which recovers some of the
rotation speed the [nginx VPS](nginx.md) loses when the host takes minutes to reprovision.
