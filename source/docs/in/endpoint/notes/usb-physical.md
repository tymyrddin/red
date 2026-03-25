# USB and physical attacks

Physical access vectors are less common in remote-first engagement scenarios but remain disproportionately effective when they apply. The reason is simple: physical presence bypasses network perimeter controls entirely, and the gap between physical security and technical security in most organisations is substantial. A device plugged into a locked workstation in an unmonitored meeting room achieves in seconds what a remote attack might not achieve at all.

## HID and USB attack devices

Human Interface Device spoofing is the most reliable USB attack category because HID drivers are loaded automatically without requiring driver installation, user consent, or elevated privileges. A device that presents itself as a USB keyboard can type keystrokes into the active window at speeds far beyond human capability.

The Rubber Ducky and its successors (Hak5 devices, the OMG Cable) automate keystroke injection. A script to open PowerShell and execute a download cradle takes under three seconds to type. The attack works regardless of OS security configuration because it operates at the HID layer, which predates and sits below most security controls.

The O.MG Cable is an Apple-compatible charging cable with embedded compute that can serve a WiFi access point for remote keyboard injection, execute payloads when connected, and exfiltrate data. It is physically indistinguishable from a legitimate cable and exploits the implicit trust most users have in cables left in meeting rooms or sent as gifts.

BadUSB-class attacks modify USB device firmware to change the device's presented identity after the initial connection. A USB storage device that reconfigures itself as a keyboard after being enumerated as storage defeats policies that block unknown storage devices while permitting HID input.

## Physical implants and supply chain

Hardware implants planted in network equipment, workstations, or servers during shipping or maintenance provide persistent access that is entirely invisible to software-based security tools. The NSA ANT catalogue, leaked in 2013, documented a range of implant capabilities at the hardware level. Commercial equivalents are available to a wider range of threat actors.

Supply chain attacks against hardware are documented at the nation-state tier: interdiction of packages in transit, insertion of implants during manufacturing, and tampering with component supply chains before hardware reaches the target organisation. The practical relevance for most red team engagements is that hardware received from vendors should be treated as a potential supply chain risk, and physical security of server rooms and network equipment matters as much as software controls.

## BIOS and firmware attacks

UEFI firmware persistence survives OS reinstallation and disk replacement because it lives in flash storage on the motherboard. Implants at this layer, such as the LoJax rootkit documented in the wild, are recoverable only by reflashing the firmware. Access to write to UEFI flash requires either a physical DMA attack, a vulnerability in a UEFI-accessible driver or application, or administrative access with the SPI flash write protection disabled.

Secure Boot, when correctly configured, prevents unsigned boot code from executing and substantially raises the bar for UEFI implants. Its effectiveness depends on the key management: systems using Microsoft's third-party UEFI certificate are vulnerable to the shim bootloader issues discovered in 2023 (BootHole and successors).

## Practical relevance

For most red team engagements, USB attacks are tested through simulated dropped device scenarios: USB drives left in car parks or reception areas to test whether users plug in unknown devices, and whether the organisation's endpoint controls detect and block automated execution. The HID injection path bypasses these controls and is relevant for testing whether physical access to a workstation (reception desk, unlocked office, tailgated server room) translates to compromise even without inserting storage media.
