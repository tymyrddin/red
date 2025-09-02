# Transport raids

Hacking the transport layer of the Internet:

* Despite attempts to make TCP as secure as possible, there still are some attacks that abuse it.
* Three major attacks are possible: Address spoofing, TCP sequence number prediction, and port scanning.
* And several minor attacks.

## Replay attack

* The origin of a replay attack can be either internal or external to the running process.
* The destination of a replay attack can either be deflected, or sent straight through.
* Interleaving messages from one process are being injected concurrently into another process
* Classic Replays do not depend on the time of the session

```text
1 External attack
    1.1 Interleaving
        1.1.1 Deflection
            1.1.1.1 Reflection to sender
            1.1.1.2 Deflection to third party
        1.1.2 Straight replay
    1.2 Classic replay
        1.2.1 Deflection
            1.2.1.1 Reflection to sender
            1.2.1.2 Deflection to third party
        1.2.2 Straight replay
2 Internal attack
    2.1 Deflection
        2.1.1 Reflection to sender
        2.1.2 Deflection to third party
    2.2 Straight replay
```

## TCP sequence number prediction attack

TCP suffers from well-known design flaws which make it possible to hijack or terminate applications that use it as their transport protocol. An SCP sequence prediction attack is an attempt to predict the sequence number used to identify the packets in a TCP connection, which can be used to forge packets, for example in a BGP Hijack.

```text
1 Blind spoofing attack (OR)
    1.1 Guess sequence number use (AND)
    1.2 Inject valid message 
2 Non-blind spoofing attack
    2.1 Sniff traffic (AND)
    2.2 Inject valid message based on sequence numbers
```

## Hijack session

Often two types of session hijacking are distinguished depending on how they are done. If the attacker directly gets involved with the target, it is called active hijacking, and if an attacker just passively monitors the traffic, it is called passive hijacking (but is really just sniffing).

```text
    1 Active
        1.1 Silence the (usually client) device with a DoS (AND)
        1.2 Take over the devices' position in the communication exchange between device and server (AND)
            1.2.1 Use TCP sequence prediction attack
        1.3 Create new user accounts on the network to gain access to the network later
    2 Passive
        2.1 Monitor the traffic between client and server
        2.2 Discover valuable information or passwords
```

## BGP hijack

BGP hijacking happens often, there is no practical way to prevent it, we have to live with it. Internet routing was designed to be a conversation between trusted parties. HTTPS encryption is backed by SSL/TLS PKI, which itself trusts Internet routing. Routing announcements are accepted practically without any validation, creating the possibility of a network operator announcing someone else's network prefixes without permission. Testing has shown that sending spoofed updates as a blind adversary is more difficult than thought, while launching this attack from a compromised/misconfigured router turned out relatively easy.

A BGP hijack can be used to disable critical portions of the Internet by disrupting Internet routing tables, force a multi-homed AS to use an alternate path to/from an outside network instead of the preferred path, disable single-homed and multi-homed AS, to blackhole traffic and in on-path attacks.

```text
1 Send from valid router (OR)
    1.1 Misconfigured (OR)
    1.2 Compromise router
2 Send from invalid router
    2.1 Gag valid router (AND)
        2.1.1 Kill router
            2.1.1.1 Power Off/Physical Layer (OR)
            2.1.1.2 Crash and prevent reboot (OR)
            2.1.1.3 Conduct denial of service against router 
        2.1.2 Steal IP Address
            2.1.2.1 ARP Spoof (OR)
            2.1.2.2 Steal MAC
    2.2 Introduce rogue router (Assume IP)
        2.2.1 Steal IP Addr
        2.2.2 More Specific Route Introduction
        2.2.3 Establish unauthorised BGP session with peer
3 Send spoofed BGP Update from Non-Router
    3.1 Conduct TCP Sequence Number Attack
    3.2 Conduct Man-in-the-Middle
4 Craft BGP Message 
```
