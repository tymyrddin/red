# Next-Generation firewalls

Traditional firewalls, such as packet-filtering firewalls, expect a port number to dictate the protocol being used 
and identify the application. If you want to block an application, you need to block a port. Unfortunately, this is 
no longer valid as many applications camouflage themselves using ports assigned for other applications. In other words, 
a port number is no longer enough nor reliable to identify the application being used. Add to this the pervasive use o
f encryption, for example, via SSL/TLS.

Next-Generation Firewall (NGFW) is designed to handle the new challenges facing modern enterprises. For example, some 
of NGFW capabilities include:

* Integrate a firewall and a [real-time Intrusion Prevention System (IPS)](../netsec/nextgen.md). It can stop detected threats in real-time.
* Identify users and their traffic. It can enforce the security policy per-user or per-group basis.
* Identify the applications and protocols regardless of the port number being used.
* Identify the content being transmitted. It can enforce the security policy in case any violating content is detected.
* Ability to decrypt SSL/TLS and SSH traffic. For instance, it restricts evasive techniques built around encryption to transfer malicious files.

A properly configured and deployed NGFW renders many attacks useless.
