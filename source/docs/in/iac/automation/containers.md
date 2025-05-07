# Spawning containers

Whichever cloud provider we chose and whatever Linux distribution they host, as long as there is Docker support, we 
can spawn the fully configured C2 backends using a couple of command lines. 

The Metasploit and SilentTrinity containers can run on the same host, but the Nginx container must run on a separate 
host. If the IP or domain gets flagged, respawn a new host and run a docker run command. Twenty seconds later, we have 
a new domain with a new IP routing to the same backends.

The following will run our Metasploit container:

```text
root@tardis:~/# docker run -dit \
-p 9990-9999:9990-9999 \
-v $HOME/.msf4:/root/.msf4 \
-v /tmp/msf:/tmp/data phocean/msf
```

And this will run the SILENTTRINITY container:

```text
root@tardis:~/# docker run -d \
-v /opt/st:/root/st/data \
-p5000-5050:5000-5050 \
barzh/silent
```

Launching the fully functioning Nginx server that redirects traffic to the C2 endpoints (The DNS record of 
`www.<customdomain>.com` should already point to the server’s public IP for this to work.:

```text
root@enterprise:~/# docker run -d \
-p80:80 -p443:443 \
-e DOMAIN="www.customdomain.com" \
-e C2IP="192.168.1.29" \
-v /opt/letsencrypt:/etc/letsencrypt \
barzh/nginx
```
