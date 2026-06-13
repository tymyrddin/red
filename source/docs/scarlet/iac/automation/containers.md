# Spawning containers

Whichever cloud provider was chosen and whatever Linux distribution they host, as long as there is Docker support,
the fully configured C2 backends can spawn using a couple of command lines.

The C2 and frontend containers usually run on separate hosts. If the IP or domain gets flagged, respawn a new host
and run a docker run command. Twenty seconds later, there is a new domain with a new IP routing to the same
backends.

The following will run the Metasploit container (built from the Dockerfile in
[metasploit.md](../backends/metasploit.md)):

```bash
docker run -dit \
    -p 8400-8500:8400-8500 \
    -v ~/.msf4:/root/.msf4 \
    -v /tmp/msf:/tmp/data \
    msf
```

And this will run a [Sliver](../backends/sliver.md) container:

```text
root@tardis:~/# docker run -d \
-v /opt/sliver:/root/.sliver \
-p 31337:31337 -p 8888:8888 \
sliver
```

Launching the fully functioning Nginx server that redirects traffic to the C2 endpoints (the DNS record of
`www.<customdomain>.com` already points to the server's public IP, otherwise this fails):

```text
root@enterprise:~/# docker run -d \
-p 80:80 -p 443:443 \
-e DOMAIN="www.customdomain.com" \
-e C2IP="192.168.1.29" \
-v /opt/letsencrypt:/etc/letsencrypt \
frontend
```
