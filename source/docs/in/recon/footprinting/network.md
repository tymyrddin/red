# Gather network information

* Domains
* Subdomains
* IP addresses
* Whois and DNS records

## Whois and IP Geolocation

Whois databases contain domain owners' personal information and are maintained by the Regional Internet Registries. **Thick whois** contains all information from all registrars for the specified set of data. **Thin whois** contains limited information about the specified set of data.

Whois query results typically include:

* Domain details
* Domain owner details
* Domain server
* Net range
* Domain expiration
* Creation and last update dates

Regional Internet Registries, which maintain the whois databases, include:

* [Reseaux IP Europeens Network Coordination Centre (RIPE)](http://www.ripe.net)
* [American Registry for Internet Numbers (ARIN)](http://www.arin.net)
* [Asia-Pacific Network Information Centre (APNIC)](http://www.apnic.net)
* [Latin America and Caribbean Network Information Centre (LACNIC)](http://lacnic.net)
* [Africa’s NIC (AFRINIC)](http://www.afrinic.net)

### IP Geolocation

IP geolocation helps find location information about a target such as country, city, postal code, ISP, and so on. This informationis useful for (planning) social engineering attacks on the target.

## DNS footprinting

DNS footprinting involves collecting information about DNS zone data, which includes information about server types and locations of key hosts in the network. 

## Network Footprinting

Network footprinting refers to the process of collecting information about the target’s network. During this process, attackers collect network range information and use the information to map the target’s network.

Network range gives attackers an insight into how the network is structured and which machines belong to the network.

Nmap can be used for network discovery. It uses raw IP packets to determine the available hosts on the network, the services offered by those hosts, operating systems they are running, firewall types that are being used, and other important characteristics.

Traceroute programs uses the ICMP protocol and the TTL field in the IP header to discover a route to the target host. It records IP addresses and DNS names of discovered routers underway. This information can be used for man-in-the-middle and other related attacks.

The results of a traceroute can also be used to collect information about network topology, trusted routers, and firewall locations, useful for creating network diagrams and planning attacks.