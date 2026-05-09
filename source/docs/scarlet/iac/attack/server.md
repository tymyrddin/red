# Use an attack server

An alternative to using an [ephemeral OS](ephemeral.md) with a bounce server, is setting up
a front-line VPS attack server on a cloud provider that accepts [anonymous payments](../bouncers/payments.md).

Configure firewall rules to allow SSH traffic from our current public IP, whether that's a Wi-Fi
hotspot at a [suitable location](location.md). Once the machine is up, connect to it using SSH.

## Hardening

Before any tooling goes on the box:

* Disable password authentication. Key only.
* Disable root SSH login. Use a non-default user with sudo.
* Run a firewall on the host (nftables or ufw), not just at the cloud edge. Allow only the ports actually in use.
* Set up unattended security upgrades, or accept that the host is short-lived enough not to need them.
* Drop SSH on a non-default port if the provider allows arbitrary inbound; this is noise reduction, not security.

## Tools

The exact toolset depends on the operation. A typical baseline:

* Nmap, masscan for reconnaissance.
* A C2 client matching the chosen [backend](../backends/landslides.md).
* Tor or a VPN client for outbound, if the host's outbound is not already laundered.
* Build tools for any payload compilation done on the host (preferable to dragging payloads through SSH from a
workstation).

Avoid installing anything that links the host to the operator: no shell history sync, no dotfile repos, no package
managers logged into personal accounts.

## Disposal

When the operation closes, destroy the host through the provider's API. Do not snapshot. Do not back up. The whole
point of a front-line attack server is that it leaves no persistent state behind.
