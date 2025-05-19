# DNS enumeration

DNS enumeration is possible by sending zone transfer requests to the DNS primary server pretending to be a client. DNS enumerating reveals sensitive domain records in response to the request.

## Tools

### dnsenum

DNSenum is perl script identifying DNS information of target.

    # dnsenum --noreverse <domain>

### dnsrecon

[dnsrecon](https://github.com/darkoperator/dnsrecon) is a Python script that provides the ability to:

* Check all NS Records for Zone Transfers.
* Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).
* Perform common SRV Record Enumeration.
* Top Level Domain (TLD) Expansion.
* Check for Wildcard Resolution.
* Brute Force subdomain and host A and AAAA records given a domain and a wordlist.
* Perform a PTR Record lookup for a given IP Range or CIDR.
* Check a DNS Server Cached records for A, AAAA and CNAME
* Records provided a list of host records in a text file to check.
* Enumerate Hosts and Subdomains using Google.

### nslookup

`nslookup` is a command line utility useful for identifying DNS infrastructure.

    # nslookup 
    > set type=any 
    > ls -d <domain>

It uses the default DNS server to get the `A` and `AAAA` records related to a domain. For example:

    nslookup clinic.thmredteam.com

```text
nslookup
set type=MX
target.com
```

Then use `nslookup` again to resolve the FQDNs of the mail servers to IP adressess.

```text
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	clinic.thmredteam.com
Address: 104.21.93.169
Name:	clinic.thmredteam.com
Address: 172.67.212.249
Name:	clinic.thmredteam.com
Address: 2606:4700:3034::ac43:d4f9
Name:	clinic.thmredteam.com
Address: 2606:4700:3034::6815:5da9
```

### nmap

Nmap is a port scanner used to identify open ports. Click Here for Nmap Cheatsheet

    # nmap -sC -sV -p53 192.168.x.0/24

### dig

dig is a command line tool for querying DNS servers. Use `dig` to perform DNS profiling of the target organisation.

To determine the IP address of a system:

    dig www.target.com +short

To determine the DNS servers:

    dig target.com NS +short

To determine the email servers for the organisation:

    dig target.com MX +short

dig` provides a lot of query options and even allows specifying a different DNS server to use. For example, we can 
use Cloudflare's DNS server with: `dig @1.1.1.1 tryhackme.com`.

    # dig axfr <domain> @<ns-domain>

### host

`host` is another useful alternative for querying DNS servers for DNS records.

    # host <domain>

For example:

    host clinic.thmredteam.com

```text
clinic.thmredteam.com has address 104.21.93.169
clinic.thmredteam.com has address 172.67.212.249
clinic.thmredteam.com has IPv6 address 2606:4700:3034::ac43:d4f9
clinic.thmredteam.com has IPv6 address 2606:4700:3034::6815:5da9
```

### fierce

Reconnaissance tool that quickly scans a target domain for DNS related vulnerabilities.

    # fierce -dns <domain>

### AltDNS

AltDNS is useful for identifying subdomains through alteration and permutation.

    git clone https://github.com/infosec-au/altdns.git 
    cd altdns 
    pip install -r requirements.txt

### DNSdumpster

[DNSdumpster.com](https://dnsdumpster.com/) is a free domain research tool that can discover hosts related to a domain. 

## Remediation

* Configure DNS servers not to send DNS zone transfers to unauthenticated hosts.
* Make sure DNS zone transfers do not contain HINFO information.
* Trim DNS zone files to prevent revealing unnecessary information.
