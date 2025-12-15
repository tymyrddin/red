# Wireless and remote access testing

When the "air gap" has WiFi.

The term "air gap" in OT security refers to the theoretical isolation of control systems from external networks 
through the simple expedient of not connecting them to anything. It's a wonderfully simple security model: if there's 
no physical connection, there can be no network intrusion. This works brilliantly right up until someone needs to 
access the system remotely, at which point the air gap acquires a bridge, and then another bridge for redundancy, 
and before long you have more bridges across your air gap than the River Ankh has crossing points.

The Ankh is famously more solid than liquid, to the point where you can almost walk across it if you're brave and 
have had your tetanus shots. The air gaps in most OT environments have achieved a similar state of solidity. They're 
still called air gaps, everyone agrees they exist, but in practice they're permeated with wireless access points, 
4G routers, Bluetooth devices, satellite links, and various other forms of electromagnetic radiation that rather 
undermine the whole "air" aspect of the gap.

At UU P&L, the official network architecture showed a pristine air gap between the control network and everything 
else. The control network was isolated, unreachable, a fortress of solitude. The reality, discovered during our 
wireless survey, was that the control network had more wireless access points than the corporate network, including 
three different 4G routers, two satellite modems, a collection of Bluetooth-enabled sensors, several Zigbee 
networks for building automation that somehow intersected with industrial controls, and one enthusiastic contractor 
who'd installed a WiFi Pineapple because he thought it was a legitimate networking device and liked the name.

Wireless and remote access testing is about finding all the radio-frequency bridges across the air gap, determining 
whether they're secure, and documenting the spectacular gap between policy (no wireless in OT zones) and reality 
(wireless everywhere, mostly unsecured).

## Wireless site surveys

Before you can test wireless security, you need to know what wireless networks exist. This is surprisingly difficult in industrial facilities, where wireless networks are often installed by contractors, maintenance staff, or well-meaning engineers who needed temporary access and implemented permanent solutions.

### Passive wireless discovery

Start with passive scanning to identify all wireless networks without transmitting:

```bash
# Put wireless adapter in monitor mode
sudo airmon-ng start wlan0

# Passive scan (doesn't transmit)
sudo airodump-ng wlan0mon

# Save results for analysis
sudo airodump-ng -w site_survey --output-format csv wlan0mon

# Let it run for at least 30 minutes to catch all networks
# Some access points beacon infrequently
```

The [Aircrack-ng suite](https://www.aircrack-ng.org/) is the standard toolkit for wireless security testing. It's been around since 2006, which in security tool terms makes it practically ancient, but it remains effective because the fundamentals of WiFi security haven't changed as much as we'd like to pretend.

### Active wireless discovery

Passive scanning finds beaconing networks, but some networks are hidden or low-power. Active scanning sends probe requests to find them:

```bash
# Active scanning (sends probe requests)
sudo airodump-ng --band abg wlan0mon

# Target specific channels with high dwell time
sudo airodump-ng --channel 1,6,11 --dwell-time 500 wlan0mon

# Look for hidden SSIDs
sudo airodump-ng --essid-regex ".*" wlan0mon
```

### Physical wireless survey

Walk the facility with a wireless adapter and laptop, creating a heat map of signal strength. Industrial facilities are large, and a wireless network barely visible from one location might be strong from another:

Survey methodology:
1. Divide facility into zones
2. Take measurements from multiple points per zone
3. Note signal strength (RSSI) at each point
4. Document physical locations of strong signals
5. Correlate with facility maps to identify likely AP locations

Tools:
- Laptop with external wireless adapter
- GPS device for location tracking (if facility is large enough)
- Facility maps for annotation
- Camera for documenting physical locations

At UU P&L, our wireless survey revealed 23 distinct wireless networks within the supposedly isolated control zone:

Authorised networks: 2
- "UU_Engineering" (WPA2-Enterprise, 802.1X)
- "UU_SCADA" (WPA2-PSK, supposedly restricted)

Unauthorised networks: 21
- "NETGEAR37" (WPA2, default password)
- "TP-LINK_5G" (Open, no encryption)
- "Contractor_WiFi" (WPA2, password: "password123")
- "TurbineMonitor" (WEP - yes, WEP in 2024)
- "MaintenanceAccess" (WPA2, password: "maintenance")
- 16 others of similar quality

Each unauthorised network represented someone who'd needed network access, couldn't get it through official channels 
(or couldn't be bothered), and implemented their own solution. The collection of wireless networks resembled nothing so much as the unofficial market stalls that spring up in Ankh-Morpork's alleys, each one technically illegal but all of them serving a genuine need that the official systems didn't address.

## Rogue access point detection

A rogue access point is an unauthorised wireless network that connects to your wired network. They're particularly dangerous because they bypass all your network security controls, creating an unmonitored bridge from wireless to wired networks.

### Identify rogues by MAC address

Every network interface has a MAC address that identifies the manufacturer. Consumer-grade access points use 
MAC addresses from consumer vendors: 

[🐙 Identify likely rogue access points by MAC OUI analysis](https://github.com/ninabarzh/power-and-light/blob/main/topics/id-rogues-by-mac-address.py)

### Identify rogues by network connection

Rogue APs connected to your network will appear in switch MAC tables:

```bash
# Query switch for connected devices
# (Requires SNMP or CLI access to switches)

# Via SNMP
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.17.4.3.1.2

# Via Cisco CLI
show mac address-table | include wireless_mac_address

# Compare MAC addresses seen on wireless survey
# with MAC addresses seen on switch ports
# Overlap = rogue AP connected to wired network
```

### Physical location of rogues

Once you've identified a rogue, find it physically:

```bash
# Directional antenna + signal strength
# Walk facility following signal strength
# Signal gets stronger as you approach the device

# Using airodump-ng
sudo airodump-ng --bssid <rogue_mac> wlan0mon

# Watch the Power column (RSSI)
# -30 dBm = very close
# -50 dBm = nearby
# -70 dBm = distant
# -90 dBm = barely visible
```

At UU P&L, we tracked down a rogue access point to a junction box in the turbine hall. It was a consumer-grade TP-Link router, connected to the control network via an Ethernet cable someone had tapped into, configured with the ESSID "TurbineRemote" and the password "1234". According to the maintenance logs, a contractor had installed it three years ago so he could "check turbine status from the car park" during night shifts. The contractor had long since left the company, but the router remained, faithfully providing unsecured wireless access to the control network.

## WPA2 and WPA3 testing

Once you've found wireless networks, test their encryption strength. WPA2 is the current standard, WPA3 is the newer (and stronger) standard, and WEP is the ancient standard that should have been extinct by 2005 but persists in industrial environments like a particularly resilient cockroach.

### WEP cracking (if you find it)

WEP is so broken that cracking it is almost trivial:

```bash
# Capture packets
sudo airodump-ng -c <channel> --bssid <ap_mac> -w wep wlan0mon

# Generate traffic if network is idle
sudo aireplay-ng -1 0 -a <ap_mac> wlan0mon  # Fake authentication
sudo aireplay-ng -3 -b <ap_mac> wlan0mon     # ARP replay attack

# Crack WEP (usually requires 40,000-80,000 IVs)
aircrack-ng wep-01.cap

# Typical time: 5-15 minutes
```

Finding WEP in 2024 is like finding a medieval drawbridge protecting a nuclear facility. It suggests that either nobody's looked at security settings since installation, or there's been an active decision to ignore security recommendations for over a decade.

### WPA2-PSK cracking

WPA2 with a pre-shared key (PSK) is vulnerable to offline dictionary attacks if the password is weak:

```bash
# Capture the 4-way handshake
sudo airodump-ng -c <channel> --bssid <ap_mac> -w capture wlan0mon

# Deauth a client to force re-authentication
# This captures the handshake
sudo aireplay-ng -0 5 -a <ap_mac> -c <client_mac> wlan0mon

# Crack with wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Or use hashcat for GPU acceleration
hcxpcapngtool -o hash.hc22000 capture-01.cap
hashcat -m 22000 -a 0 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

Success depends entirely on password strength:

```
"password" - cracks in seconds
"password123" - cracks in seconds
"Password123!" - cracks in minutes
"UU_P&L_Turbine_2024" - cracks in hours (if in wordlist)
"xK9$mP2#vL8@nQ4%" - probably won't crack (if not in wordlist)
```

At UU P&L, we tested 23 wireless networks:

- WEP networks (2): Cracked in under 10 minutes each
- WPA2 networks with default passwords (8): Cracked in under 1 minute each
- WPA2 networks with weak passwords (7): Cracked in 15 minutes to 3 hours
- WPA2 networks with strong passwords (4): Did not crack (tested for 24 hours)
- WPA2-Enterprise (802.1X) (2): Requires different approach

### WPA2-Enterprise testing

WPA2-Enterprise uses 802.1X authentication with a RADIUS server. It's more secure than PSK but has its own vulnerabilities:

```bash
# Evil Twin attack with EAP credential harvesting
# Using eaphammer
sudo eaphammer -i wlan0 --auth wpa-eap --essid "UU_Engineering" \
    --creds --negotiate balanced

# This creates a fake AP that looks identical to the real one
# When clients connect, it attempts to negotiate weak EAP methods
# Can capture credentials if client doesn't validate certificates
```

The success of this attack depends on whether clients validate RADIUS server certificates. Many don't, particularly older devices or devices configured by people who clicked "Next" through all the security warnings.

### WPA3 testing

WPA3 is designed to resist offline dictionary attacks through Simultaneous Authentication of Equals (SAE):

```bash
# WPA3 cracking requires active attack (no offline cracking)
# Using wpa_supplicant with modified configuration

# Downgrade attack: Try to force AP to accept WPA2
# If AP supports both WPA3 and WPA2 (transition mode)
# Some clients/APs may downgrade to WPA2
```

WPA3 is significantly more secure than WPA2, but adoption in OT environments is slow because it requires hardware support and many industrial devices are old enough that WPA3 didn't exist when they were manufactured.

## Bluetooth and other wireless protocols

Bluetooth Low Energy (BLE) is increasingly common in industrial sensors and IoT devices. It's designed for low power consumption, which is good for battery life but often comes with simplified (read: weak) security.

### Bluetooth device discovery

```bash
# Standard Bluetooth discovery
hcitool scan

# BLE discovery (requires BLE adapter)
sudo hcitool lescan

# Or use dedicated BLE scanner
sudo bluetoothctl
[bluetooth]# scan on

# List discovered devices
[bluetooth]# devices
```

### Bluetooth security testing

Ubertooth One is a specialised Bluetooth security testing device:

```bash
# Capture Bluetooth traffic with Ubertooth
ubertooth-btle -f -c capture.pcap

# Follow specific device
ubertooth-btle -f -t <target_mac>

# Analyse with Wireshark
wireshark capture.pcap
```

Common Bluetooth vulnerabilities in OT:

- Default PINs: Many industrial Bluetooth devices use "0000" or "1234"
- No encryption: Some devices don't encrypt at all
- Weak pairing: PIN-based pairing is vulnerable to brute force
- No authentication: Some devices accept connections from any source

At UU P&L, we found 47 Bluetooth devices in the turbine control area:

Industrial sensors: 23
- Temperature sensors (12)
- Pressure sensors (7)
- Vibration monitors (4)

Operator devices: 18
- Smartphones (personal devices)
- Tablets running maintenance software

Unknown devices: 6
- Discovered during scan but couldn't identify
- Two appeared to be fitness trackers
- Four unidentified (concerning)

The industrial sensors were using Bluetooth to transmit readings to nearby data loggers. They used no encryption and no authentication. Anyone within Bluetooth range (approximately 10 metres) could read the sensor data or potentially inject false readings.

### Zigbee and other IoT protocols

Zigbee is common in building automation and increasingly appearing in industrial IoT:

```bash
# Zigbee analysis with HackRF or similar SDR
# Zigbee uses 2.4 GHz band

# Using killerbee framework for Zigbee testing
zbstumbler -i <channel>  # Discover Zigbee networks
zbdump -f dump.pcap      # Capture Zigbee traffic
```

## Unauthorised remote signal access

Remote access does not always arrive through approved cables, blessed firewalls, or paperwork signed in triplicate. 
Sometimes it simply *appears*. A small, cheap signal box, installed by a contractor “just for testing”, can provide 
instant remote access into networks that everyone swears are isolated.

No trenching. No approvals. No IT knowledge. Just a blinking light and a very long invisible wire.

In Ankh‑Morpork terms: a private clacks relay nailed to the back of the machinery cupboard and never mentioned again.

### Detecting unauthorised signal links

```bash
# Network-based detection
# Look for unexplained external traffic paths or odd latency patterns
# Remote backhaul tends to behave differently from internal wiring

# Physical inspection
# Walk the site and actually look
# Small signal boxes often have antennas, crystals, or suspiciously warm casings
# Frequently hidden where nobody expects modernity to intrude

# Signal detection
# Scan for strong radio or thaumic emissions where none should exist
hackrf_sweep -f 700:6000 -w output.csv
# Look for persistent signals in common telecom bands
# Or anything humming quietly to itself
```

If it was installed because “it was quicker”, it was also hidden because “IT would never approve it”.

### Common hiding places for unauthorised signal devices

At UU Power & Light, unauthorised signal gateways were discovered in:

1. Junction boxes: The classic. A contractor installs a signal device, runs a cable to the control system, closes the box, and leaves whistling innocently.

2. Equipment cabinets: Tucked behind PLCs, relays, or anything large enough to block a casual glance. Out of sight, out of audit.

3. False ceilings: One device was found resting on ceiling tiles above the control room, with a cable politely lowered through an existing conduit. Gravity is very helpful to attackers.

4. Under desks: The least imaginative option, and therefore the most successful. Nobody ever looks under desks unless something is on fire.

### Testing unauthorised remote access

Once discovered, assume the device is hostile until proven otherwise. Then test it.

```bash
# Scan for management interfaces
nmap -p 80,443,8080 <device_ip>

# Default credentials (remarkably popular)
# admin/admin
# admin/password
# admin/(blank)
# user/user

# Check routing reachability
traceroute <internal_target>

# Check for absence of meaningful firewalling
nmap -p- <internal_target>
```

The signal gateway discovered at UU P&L had:

* Default credentials (`admin/admin`)
* No separation between external signal access and the control network
* Full routing into operational systems
* A remote access service enabled with factory settings
* A management interface reachable from outside the facility
* Uptime: *1,247 days* (just over three years)

In short, it was a perfect back door.

Anyone, anywhere, with basic technical knowledge and a passing curiosity could have connected remotely, logged in 
without resistance, and gained full access to the control network. It had been quietly doing its job for over three 
years.

Nobody noticed. Nobody logged it. Everyone assumed the isolation was real.

It never is.

## Satellite links

If it has a shed, a fence, and a sign saying Authorised Personnel Only, satellite has probably been considered. 
Some facilities use satellite communications for remote sites or backup connectivity. Satellite links have unique 
security considerations:

### Physical security

Satellite dishes are outdoors and accessible. An attacker with physical access can:
- Tap into the coaxial cable
- Replace the modem with a compromised version
- Install a secondary receive dish to intercept traffic

### Signal interception

Satellite signals broadcast over a wide area. Anyone within the footprint can receive them:

VSAT (Very Small Aperture Terminal) systems typically use:
- Ku-band (12-18 GHz)
- Ka-band (26.5-40 GHz)

If traffic is unencrypted, it can be intercepted with:
- Satellite dish
- Appropriate LNB (Low-Noise Block downconverter)
- SDR (Software-Defined Radio) or satellite receiver
- Decoding software

Cost: €500-2000 for equipment
Difficulty: Moderate (requires some RF knowledge)

### Testing satellite security

```bash
# Check if traffic is encrypted
# Capture traffic at the modem
tcpdump -i eth0 -w satellite_traffic.pcap

# Analyse protocols
wireshark satellite_traffic.pcap

# Look for:
# - Unencrypted HTTP
# - Unencrypted Modbus or other OT protocols
# - Clear-text credentials
# - Sensitive operational data

# Many older satellite systems use no encryption
# or use weak encryption (DES, single DES)
```

At UU P&L, the main facility had no satellite links, but they had a remote pumping station that used VSAT for monitoring. Analysis showed:
- Traffic between pump station and central SCADA: unencrypted
- Modbus traffic: unencrypted
- Web interface traffic: HTTP, no HTTPS
- Data visible: Pump status, flow rates, reservoir levels

An attacker with a satellite dish pointed at the right part of the sky could intercept all this data. They'd know exactly when the facility was pumping, how much, and to where. For a competitor or nation-state actor, this would be valuable intelligence.

## Radio systems

Some industrial facilities use private radio networks for communication:

### Common radio systems in OT

- SCADA radio networks: License-free bands (433 MHz, 868 MHz, 2.4 GHz)
- Push-to-talk radios: Used by maintenance and operations
- Paging systems: For emergency notifications
- Telemetry systems: Remote sensor data transmission

### Radio security testing

[HackRF One](https://greatscottgadgets.com/hackrf/) is a software-defined radio that can transmit and receive across a wide frequency range:

```bash
# Scan for active frequencies
hackrf_sweep -f 400:900

# Receive on specific frequency
hackrf_transfer -r capture.bin -f 433920000 -s 2000000

# Analyse with GNU Radio or inspectrum
inspectrum capture.bin
```

### Common radio vulnerabilities

1. No encryption: Many industrial radio systems transmit in clear
2. Weak authentication: Some use no authentication at all
3. Jamming susceptibility: Radio is easy to jam
4. Replay attacks: Captured commands can be replayed

At UU P&L, the maintenance team used two-way radios for coordination. These radios operated on license-free PMR446 frequencies with no encryption. Anyone with a €30 radio from a camping shop could listen to maintenance communications, including:
- Schedules ("We're starting turbine maintenance at 14:00")
- Locations ("I'm at Turbine 2 now")
- Problems ("The access control card reader at Gate 3 is broken again")
- Security bypass methods ("Just tailgate through the door, the card system is down")

This isn't a critical security issue, but it's useful reconnaissance for an attacker planning physical access.

## The uncomfortable truth about air gaps

The fundamental problem with air gaps in OT environments is that they do not survive contact with reality.

Engineers need remote access for troubleshooting. Maintenance contractors need to upload updates. Vendors want to monitor their equipment. Management wants dashboards they can glance at between meetings. Every one of these requirements creates a bridge across what was meant to be empty space.

The result is that most “air‑gapped” OT networks are nothing of the sort. They are connected via ad‑hoc wireless links, unauthorised signal gateways, satellite connections, vendor‑managed remote access, and a variety of other mechanisms installed to solve legitimate operational problems. Taken together, they quietly dismantle the isolation the air gap was supposed to provide.

At UU Power & Light, the gap between policy and reality was… ambitious.

### Official policy

“Control network is air‑gapped from all external networks. No wireless devices permitted in OT zones. Remote access 
via secure jump hosts only.”

### Actual implementation

* 23 unauthorised wireless networks
* 4 unauthorised external signal gateways providing direct internet access
* 1 satellite link with no encryption
* 6 vendor remote access connections (always on)
* 47 Bluetooth devices
* Multiple radio systems
* “Air gap” more accurately described as *radio soup*

This does not mean the UU P&L security team was incompetent. It means operational reality overwhelmed security policy.

Every unauthorised connection existed for a reason. The wireless network in the turbine hall existed because engineers 
needed network access during maintenance. The external signal gateway existed because a contractor needed to check 
system status remotely. The Bluetooth sensors existed because they were easier to install than pulling new cables 
through forty years of accumulated pipework and optimism.

Fixing this requires more than simply ripping out unauthorised devices (although that is a good start). It requires 
understanding *why* people bypassed controls and providing alternatives that are secure **and** usable.

If accessing an engineering workstation requires twenty minutes of approvals and ritual authentication, engineers 
will create their own shortcuts. If remote troubleshooting means a two‑hour drive at two in the morning, someone 
will install a private remote link and promise to remove it later.

The goal is not perfect isolation. It is **controlled, visible, and intentional connectivity** that is easy enough 
to use that people stop inventing their own solutions.

That is harder than implementing technical controls. It requires balancing security with operational reality and 
persuading people whose primary concern is keeping turbines spinning, not satisfying security diagrams.

But it is the only approach that works for longer than a maintenance cycle.

