# Guessing IPv6 Interface IDentifiers (IIDs)

In IPv6, every device on a network has a unique address. Each address has two parts: the network prefix (like the “street” your device is on) and the Interface Identifier, or IID (like the “house number”). The IID is usually 64 bits long and identifies the specific device on that network.

Sometimes, the IID is easy to guess. If an attacker can predict your IID, they can target your device, scan for vulnerabilities, or try to impersonate it. In this guide, we explain common IID patterns and how to “guess” them—so you understand the risks and how to defend against them.

* **Note: Do not use this knowledge to attack other networks. Practice in lab environments like the RIPE labs.** *

Knowing how IIDs can be guessed helps:

* Recognise predictable patterns in your network.
* Protect devices with privacy extensions (RFC 4941) or stable opaque IIDs (RFC 7217).
* Configure lab exercises safely.
* Understand how attackers might try to scan or fingerprint hosts.

## 1. EUI-64 Based IIDs

What it is:

* Many devices automatically generate their IID from the MAC address (a hardware ID for your network card) using the EUI-64 format.
* The 48-bit MAC is split and combined with `ff:fe` to form the 64-bit IID.

Why it is predictable:

* MAC addresses are fixed and globally unique.
* If an attacker knows a device’s MAC (e.g., by sniffing Wi-Fi traffic or checking ARP tables), they can calculate the IID.

Example:

```
MAC: 00:16:3E:AB:CD:EF
IID: 0216:3EFF:FEAB:CDEF
IPv6: 2001:db8::0216:3EFF:FEAB:CDEF
```

Lab exercise:

* In a lab, find your MAC address using `ip link`.
* Convert it to an IID using the EUI-64 method. Compare it with the IID your device actually uses.

## 2. Low-bits / Trivial IIDs

What it is:

* Some devices use simple, low-numbered IIDs, like `::1` or `::2`.
* Often found in lab setups, routers, or test devices.

Why it is predictable:

* Attackers can easily scan the first few addresses in a subnet without guessing randomly.

Example:

```
2001:db8::1
2001:db8::2
```

Lab exercise: Ping the first few addresses in a lab subnet to see which respond.

## 3. IPv4-based IIDs

What it is:

* Some devices embed their IPv4 address into the IPv6 IID for dual-stack networks.
* This helps networks transition from IPv4 to IPv6 but is predictable.

Example:

```
IPv4: 192.0.2.10
IID: ::c000:020a
IPv6: 2001:db8::c000:020a
```

Lab exercise: Take your lab IPv4 address and convert it to hexadecimal. Compare it with your IPv6 IID.

## 4. Service port-based IIDs

What it is:

* Some IIDs encode service information, like which port the device runs a service on.
* Less common, but can be guessed if the pattern is known.

Example:

* A web server running on port 80 might have an IID ending in `0x0050`.

Lab exercise: If you run multiple services in your lab VM, check if the IIDs match the ports.


## 5. Wordy / Human-readable IIDs

What it is:

* Devices may use “wordy” IIDs based on hostnames or other mnemonic patterns.
* Common in labs or small networks for easy identification.

Example:

```
Hostname: alice-laptop
IID: ::616C:6963:65XX
IPv6: 2001:db8::616C:6963:65XX
```

Lab exercise: Look at your hostname and see if any portion is encoded in your IPv6 address.

## 6. Sequential IIDs

What it is:

* Some networks assign IIDs sequentially.
* Each new host gets the next number in the series.

Example:

```
2001:db8::1
2001:db8::2
2001:db8::3
```

Lab exercise: Start at `::1` and ping incrementally in a lab subnet to see which addresses respond.

## More ideas

You can also find information in:

* RIR databases (Whois), usually up to /48s
* Log files on servers where you have the IPs of clients
* Public archives such as mailing list archives  (IP addresses in e-mail headers)
* “Collaborative” software like BitTorrent.

## Mitigation suggestions

* Enable privacy extensions: Generates temporary, random IIDs.
* Use stable, semantically opaque IIDs: Prevents guessing even if the MAC is known.
* Avoid low-numbered or sequential IIDs in production networks.
* Monitor network traffic: Detect repeated scanning attempts.

