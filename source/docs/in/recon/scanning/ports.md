# Port scanning

## Types of scans

| Port Scan Type                 | Example Command                               |
|:-------------------------------|:----------------------------------------------|
| TCP Connect Scan               | nmap -sT <IP>                                 |
| TCP SYN Scan                   | sudo nmap -sS <IP>                            |
| UDP Scan                       | sudo nmap -sU <IP>                            |
| TCP Null Scan                  | sudo nmap -sN <IP>                            |
| TCP FIN Scan                   | sudo nmap -sF <IP>                            |
| TCP Xmas Scan                  | sudo nmap -sX <IP>                            |
| TCP Maimon Scan                | sudo nmap -sM <IP>                            |
| TCP ACK Scan                   | sudo nmap -sA <IP>                            |
| TCP Window Scan                | sudo nmap -sW <IP>                            |
| Custom TCP Scan                | sudo nmap --scanflags URGACKPSHRSTSYNFIN <IP> |
| Spoofed Source IP              | sudo nmap -S SPOOFED_IP <IP>                  |
| Spoofed MAC Address            | --spoof-mac SPOOFED_MAC                       |
| Decoy Scan                     | nmap -D DECOY_IP,ME <IP>                      |
| Idle (Zombie) Scan             | sudo nmap -sI ZOMBIE_IP <IP>                  |
| Fragment IP data into 8 bytes  | -f                                            |
| Fragment IP data into 16 bytes | -ff                                           |

## Options

| Option                 | Purpose                                  |
|:-----------------------|:-----------------------------------------|
| -p-                    | all ports                                |
| -p1-1023               | scan ports 1 to 1023                     |
| -F                     | 100 most common ports                    |
| -r                     | scan ports in consecutive order          |
| -T<0-5>                | T0 being the slowest and T5 the fastest  |
| --max-rate 50          | rate <= 50 packets/sec                   |
| --min-rate 15          | rate >= 15 packets/sec                   |
| --min-parallelism 100  | at least 100 probes in parallel          |
| --source-port PORT_NUM | specify source port number               |
| --data-length NUM      | append random data to reach given length |

Null, FIN, and Xmas scan provoke a response from closed ports, while Maimon, ACK, and Window scans provoke a response 
from open and closed ports.

| Option   | Purpose                               |
|:---------|:--------------------------------------|
| --reason | explains how Nmap made its conclusion |
| -v       | verbose                               |
| -vv      | very verbose                          |
| -d       | debugging                             |
| -dd      | more details for debugging            |