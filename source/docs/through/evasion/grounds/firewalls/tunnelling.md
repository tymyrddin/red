# Evasion using port tunnelling

Port tunneling is also known as port forwarding and port mapping. In simple terms, this technique forwards the 
packets sent to one destination port to another destination port. For example, packets sent to port 80 on one 
system are forwarded to port 8080 on another system.

Consider the following case: An SMTP server listening on port 25. It is not possible to connect to the SMTP server 
because the firewall blocks packets from the Internet sent to destination port 25. Packets sent to destination port 
443 are not blocked, so we can send packets to port 443, and after they pass through the firewall, we forward them 
to port 25. Assume we can run a command of our choice on one of the systems behind the firewall. We can use that 
system to forward our packets to the SMTP server:

    ncat -lvnp 443 -c "ncat TARGET_SERVER 25"


* `-lvnp 443` listens on TCP port `443`. Because the port number < `1024`, run `ncat` as root.
* `-c` or `--sh-exec` executes the given command via `/bin/sh`.
* `ncat TARGET_SERVER 25` will connect to the target server at port `25`.

As a result, ncat will listen on port `443`, but it will forward all packets to port `25` on the target server. 

| ![Port tunnelling](/_static/images/tunnelling.png) |
|:--:|
| In this case, the firewall is blocking port 25 and allowing port 443, port tunneling is <br>an efficient way to evade the firewall. |

## Lab

We have a web server listening on the HTTP port, `80`. The firewall is blocking traffic to port `80` from the 
untrusted network; and traffic to TCP port `8008` is not blocked. There is a vulnerable web-form to set up the ncat 
listener that forwards the packets received to the forwarded port. Using port tunneling, browse to the web server 
and retrieve the flag.

Set up a port forwarding from port 80 to 8008 on the webserver from the vulnerable form hosted on port 8080 using the 
vulnerable form:

    ncat -lvnp 8008 -c "ncat localhost 80"

On the attacker machine, try to connect netcat to the server with the non-filtered port in the firewall `8008` and request the website with 
a `GET / HTTP` request :

    # nc TARGET_IP 8008

Flag!
