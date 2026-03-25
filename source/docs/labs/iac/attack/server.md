# Use an attack server

An alternative to using an [ephemeral OS](ephemeral.md) with a [bounce server](../bouncers/README.md), is setting up 
a front-line VPS attack server on a cloud provider that accepts [anonymous payments](../bouncers/payments.md).

Configure firewall rules to allow SSH traffic from our current public IP, whether that’s a Wi-Fi
hotspot at a [suitable location](location.md). Once the machine is up, connect to it using SSH.

Install the necessary tools.

