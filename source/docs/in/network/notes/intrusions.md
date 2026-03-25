# Wireless as an access path

Wireless networks remain a viable initial access vector because they dissolve the physical boundary that wired infrastructure assumes. A corporate building with locked server rooms and badge-access may still broadcast several wireless networks detectable from the car park. The proliferation of wireless beyond the laptop and phone, into infrastructure components, industrial sensors, signage, and surveillance, means that in many environments wireless access is an attack surface that is rarely hardened to the same standard as the wired edge.

## WPA2 and the PMKID attack

WPA2 personal networks are vulnerable to offline dictionary attacks if a four-way handshake can be captured. The traditional approach requires a connected client: sending a deauthentication frame to force the client to reconnect, then capturing the resulting handshake. The deauthentication frame is unauthenticated in 802.11 and will be accepted by most clients even without being associated to the network.

```bash
# Capture the handshake
airmon-ng start wlan0
airodump-ng -c <channel> --bssid <AP-MAC> -w capture wlan0mon
aireplay-ng -0 5 -a <AP-MAC> -c <client-MAC> wlan0mon
```

The PMKID attack does not require a connected client. It recovers the PMKID value from a single EAPOL frame sent by the access point during an association attempt. The PMKID is computed from the PMK (which is derived from the passphrase), the AP MAC address, and the client MAC address, so it can be subjected to the same offline dictionary attack as a full handshake.

```bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o hash.22000 pmkid.pcapng
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt
```

WPA3 introduced the Simultaneous Authentication of Equals handshake, which replaced the pre-shared key derivation with a Diffie-Hellman exchange and eliminated offline dictionary attacks. The Dragonblood vulnerabilities disclosed in 2019 demonstrated downgrade attacks and timing side-channels against early WPA3 implementations, though most of these have been patched. WPA3 transitions mixed networks that support both WPA2 and WPA3 remain vulnerable to downgrade to WPA2.

## Evil twin and captive portal attacks

An evil twin access point broadcasts the same SSID as a legitimate network with a stronger signal, causing clients to associate with the attacker instead. Once associated, the attacker can intercept traffic, strip TLS if the client does not enforce HSTS, and present credential-harvesting pages through a rogue captive portal.

The karma attack extends this: rather than broadcasting a specific SSID, a karma-capable access point responds to probe requests from clients searching for previously connected networks. A client broadcasting the SSID "CorpWifi" as it moves through a building will receive a response from the rogue AP and attempt to associate.

Hostapd-wpe combined with hostapd-2.6 or later can host a rogue WPA2-Enterprise network that captures PEAP credentials. Many enterprise deployments validate the server certificate weakly or not at all; clients will complete the inner authentication and deliver the NTLMv2 hash to the rogue AP.

## 802.1X and enterprise wireless

802.1X port-based access control requires a successful RADIUS authentication before a wireless client is admitted to the network. The security of this model depends entirely on whether clients validate the RADIUS server's certificate and refuse connections to servers presenting unexpected certificates.

Misconfigured 802.1X clients, particularly Windows machines using PEAP-MSCHAPv2 without certificate validation, will authenticate to any server presenting a self-signed certificate. The captured MSCHAPv2 exchange can be relayed or cracked offline. EAP-TLS configurations using client certificates are substantially more resistant, though stolen certificate files from a compromised endpoint can bypass this control.
