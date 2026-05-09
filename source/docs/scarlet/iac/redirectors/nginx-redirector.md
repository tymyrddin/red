# Nginx redirector

A redirector takes inbound traffic from the target's network and forwards only the parts that match a known beacon
to the frontend. Everything else goes to a cover site.

This is one layer thinner than the [frontend nginx](../frontend/nginx.md). The frontend terminates TLS for the
cover site and routes to backends. The redirector sits closer to the target, on cheap, burnable hosts, and only
knows where the next hop is.

## Pattern

```text
target ── HTTPS ──> redirector (nginx) ── HTTPS ──> frontend (nginx) ── HTTP ──> backend (C2)
```

## Minimal config

`/etc/nginx/conf.d/redir.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name www.<customdomain>.com;

    ssl_certificate     /etc/letsencrypt/live/<customdomain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<customdomain>/privkey.pem;

    # Beacon URI prefix forwarded to the frontend
    location /api/v2/ {
        proxy_pass            https://frontend.<otherdomain>.com;
        proxy_set_header      Host frontend.<otherdomain>.com;
        proxy_ssl_server_name on;
    }

    # Everything else gets the cover page
    location / {
        return 301 https://www.example-cover-site.com$request_uri;
    }
}
```

Match the `/api/v2/` prefix to the beacon profile of the chosen [C2](../backends/landslides.md). Pick something
boring that the cover site could plausibly serve.

## Rotation

* Provision the redirector via [Terraform or cloud-init](../automation/providers.md).
* Generate a fresh certificate per host.
* When the IP is burned, destroy the host and rebuild. The frontend stays put, the next redirector points at it
under a new name.

## User-Agent and source filters

Drop traffic that does not look like the beacon profile early:

```nginx
if ($http_user_agent !~* "(Mozilla|Googlebot)") { return 404; }
if ($geoip_country_code !~ "(US|GB|NL)")        { return 404; }
```

This frustrates lazy scanners and reduces the amount of noise the frontend has to filter.
