# Infrastructure frontend

The attack infrastructure frontend interacts with the target. It is unique to each operation or target, and
replaced every few days.

To containerise the Nginx server that routes calls to either the C2 backend or the cover site, use
[jonasal/nginx-certbot](https://github.com/JonasAlfredsson/docker-nginx-certbot) as the base image. It handles
Let's Encrypt certificate issuance and renewal, and is actively maintained (the staticfloat image it descended
from was archived in 2022).

## Dockerfile

`~/nginx/Dockerfile`:

```text
# The base image with scripts to configure Nginx and Let's Encrypt
FROM jonasal/nginx-certbot:latest

# Copy a template Nginx configuration
COPY *.conf /etc/nginx/conf.d/

# Copy phony HTML web pages
COPY --chown=www-data:www-data html/* /var/www/html/

# Small script that replaces __DOMAIN__ with the ENV domain value, same for IP
COPY init.sh /scripts/
ENV DOMAIN="www.customdomain.com"
ENV C2IP="192.168.1.29"
ENV CERTBOT_EMAIL="contact@protonmail.com"

CMD ["/bin/bash", "/scripts/init.sh"]
```

## Nginx config

`~/nginx/route.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name __DOMAIN__;

    ssl_certificate     /etc/letsencrypt/live/__DOMAIN__/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/__DOMAIN__/privkey.pem;

    # Beacon paths routed to the backend C2 over the docker bridge
    location ~ ^/(api/v2|cdn-cgi/trace) {
        proxy_pass         http://__C2IP__;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
    }

    # Everything else served from the cover site
    location / {
        root  /var/www/html;
        index index.html;
    }
}

server {
    listen 80;
    server_name __DOMAIN__;
    return 301 https://$host$request_uri;
}
```

## Init script

`~/nginx/init.sh`:

```bash
#!/bin/bash
set -e

sed -i "s/__DOMAIN__/${DOMAIN}/g" /etc/nginx/conf.d/route.conf
sed -i "s/__C2IP__/${C2IP}/g"     /etc/nginx/conf.d/route.conf

# Hand off to the upstream entrypoint, which provisions the certificate and runs nginx
exec /scripts/start_nginx.sh
```

## Cover HTML

`~/nginx/html/index.html`: any plausible static page that fits the [domain category](masquerading.md). Avoid the
default Nginx welcome page; that alone is a fingerprint.

## Build and run

```bash
docker build -t frontend ~/nginx
docker run -d \
    -p 80:80 -p 443:443 \
    -e DOMAIN="www.customdomain.com" \
    -e C2IP="192.168.1.29" \
    -v /opt/letsencrypt:/etc/letsencrypt \
    frontend
```

The DNS record of `www.<customdomain>.com` already points to the host's public IP, otherwise Let's Encrypt
cannot issue.

## Cheatsheets

* [Docker cheatsheet](https://dockerlabs.collabnix.com/docker/cheatsheet/)