# Evasion via route manipulation

Evasion via route manipulation includes:

* Relying on source routing
* Using proxy servers

## Relying on source routing

Source routing can be used to force the packets to use a certain route to reach their destination. Nmap provides 
this feature using the option `--ip-options`. Nmap offers loose and strict routing:

* Loose routing can be specified using `L`. For example, `--ip-options "L 10.10.10.50 10.10.50.250"` requests that 
scan packets are routed through the two provided IP addresses.
* Strict routing can be specified using `S`. Strict routing requires setting every hop between the originating system 
and the target host. For example, `--ip-options "S 10.10.10.1 10.10.20.2 10.10.30.3"` specifies that the packets go 
via these three hops before reaching the target host.

## Using proxy servers

The use of proxy servers can help hide the source machine. Nmap offers the option `--proxies` that takes a 
comma-separated list of proxy URLs. Each URL must be expressed in the format `proto://host:port`. Valid protocols 
are `HTTP` and `SOCKS4`. Authentication is not currently supported.

As an example, instead of running nmap `-sS MACHINE_IP`, edit the Nmap command to something like:

    nmap -sS HTTP://PROXY_HOST1:8080,SOCKS4://PROXY_HOST2:4153 MACHINE_IP

This way, the scan goes through HTTP proxy host1, then SOCKS4 proxy host2, before reaching the target. 

Using a browser to connect to the target, it would be simple to pass the traffic via a proxy server. Other 
network tools provide their own proxy settings that can be used to hide the traffic source.

Proxy chaining is also an option that helps an attacker to maintain their Internet Anonymity. Some examples of 
proxy tools are Proxy Switcher, CyberGhost VPN, Tor, CCProxy, Hotspot Shield, etc.

## Resources

* [Penetration testing: TOR, VPN or proxy](https://resources.infosecinstitute.com/topic/penetration-testing-tor-vpn-or-proxy/)
