# Bluetooth and short-range radio

Bluetooth and Bluetooth Low Energy have become ubiquitous beyond consumer electronics. BLE is the communication substrate for industrial sensors, medical devices, building automation controllers, smart locks, and proximity-based access systems. The attack surface is proportionally larger than most network security programmes acknowledge, partly because Bluetooth traffic is not captured by the same monitoring infrastructure that covers wired and WiFi segments.

## Bluetooth classic versus BLE

Classic Bluetooth operates in the 2.4 GHz band using frequency-hopping spread spectrum across 79 channels. It supports profiles for audio, file transfer, serial communication, and human interface devices. The security model depends on pairing: devices exchange a link key during the pairing process, and subsequent connections authenticate using a challenge-response protocol derived from that key.

BLE operates on 40 channels with a similar frequency-hopping mechanism but uses a completely different protocol stack. It is designed for low-power intermittent communication and introduces its own pairing and bonding model. BLE advertising packets are broadcast without authentication, making device discovery trivial. The advertising data frequently includes device name, service UUIDs, and manufacturer-specific data that identifies the device type.

## KNOB and BIAS

The Key Negotiation of Bluetooth (KNOB) attack, disclosed in 2019, exploits a weakness in the entropy negotiation during Bluetooth classic pairing. An attacker positioned within radio range of both devices during pairing can manipulate the LMP negotiation to reduce the session key entropy to as little as one byte, making brute-force decryption of the session feasible in real time.

The Bluetooth Impersonation Attacks (BIAS) research demonstrated that the authentication procedure in Bluetooth classic could be manipulated to impersonate a previously paired device without knowing the long-term key, by exploiting the asymmetry between legacy and secure authentication modes. Devices that had been paired at some point in the past remained vulnerable to impersonation by an attacker who had recovered the device's Bluetooth address.

## BLE proximity and relay attacks

BLE proximity systems, used for physical access control, vehicle keyless entry, and smartphone-based authentication, make an implicit assumption that the BLE signal originates from a device physically close to the reader. Relay attacks defeat this assumption by capturing the BLE advertisement from a device at a distance and retransmitting it next to the reader, making the device appear present without the user being aware.

This attack requires two radio nodes: one near the legitimate device and one near the reader, connected by any high-speed channel. The total relay latency must fall within the proximity measurement threshold of the target system. Many commercial proximity systems do not implement distance bounding protocols and are therefore vulnerable to relay regardless of signal strength.

## Scanning and enumeration

`btlejuice` and `bettercap` provide BLE interception and mitm capabilities. Passive scanning with `hcitool lescan` or `bluetoothctl` enumerates advertising devices without any interaction. `gatttool` reads GATT attribute values from BLE devices that do not require authenticated connections, which covers a substantial proportion of IoT devices in practice.

```bash
# Scan for BLE advertising devices
hcitool lescan

# Read GATT attributes from a device
gatttool -b <device-MAC> --interactive
> connect
> primary
> char-read-hnd 0x0001
```

The practical value of BLE reconnaissance during an engagement depends on what the target deploys. A building with BLE-based access control, medical facility with connected monitoring equipment, or industrial site with BLE sensor networks each presents different attack paths from the same radio proximity.
