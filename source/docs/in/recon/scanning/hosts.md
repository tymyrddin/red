# Live host discovery

## Types of scans

ARP, ICMP, TCP, and UDP can detect live hosts. Any response from a host is an indication that it is online. 

| Scan Type                      | Example Command                               |
|:-------------------------------|:----------------------------------------------|
| ARP Scan                       | sudo nmap -PR -sn <IP>/24                     |
| ICMP Echo Scan                 | sudo nmap -PE -sn <IP>/24                     |
| ICMP Timestamp Scan            | sudo nmap -PP -sn <IP>/24                     |
| ICMP Address Mask Scan         | sudo nmap -PM -sn <IP>/24                     |
| TCP SYN Ping Scan              | sudo nmap -PS22,80,443 -sn <IP>/30            |
| TCP ACK Ping Scan              | sudo nmap -PA22,80,443 -sn <IP>/30            |
| UDP Ping Scan                  | sudo nmap -PU53,161,162 -sn <IP>/30           |

##  Options

| Option | Purpose                           |
|:-------|:----------------------------------|
| -n     | no DNS lookup                     |
| -R     | reverse-DNS lookup for all hosts  |
| -sn    | host discovery only               |