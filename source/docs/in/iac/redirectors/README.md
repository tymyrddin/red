# Introduction

Strategic redirector deployment creates essential operational buffers between compromised endpoints and core 
infrastructure. These proxy nodes absorb reputation damage and geofencing attempts while allowing rapid rotation 
of exposed ingress points. Properly configured redirector chains can maintain reliable callback channels even when 
individual nodes are discovered and neutralized, with automated provisioning ensuring new proxy instances can be 
deployed within minutes of detection events.

* Redirectors proxy requests coming from the target back to our attack infrastructure.
* Reusing IP addresses will immediately attract attention of someone on the blue team
* If the IP address of a C2 server controlling dozens of machines on a target is blacklisted, we must be able to roll out a new server in a matter of seconds with a fresh IP to receive new connections, without interrupting ongoing jobs not subject to the IP ban.
* We need to be able to serve multiple clients/targets. Too much from one IP address makes for suspicions.

## How?

* Set up a redirector for each specific operation.
* Note the solution with [bounce servers](../bouncers/README.md) is much more elegant and quick.
* [Professor-plum/Presentations](https://github.com/Professor-plum/Presentations)
