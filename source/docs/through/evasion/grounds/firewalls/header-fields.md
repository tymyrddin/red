# Evasion via modifying header fields

Nmap allows you to control various header fields that might help evade the firewall. You can:

* Set IP time-to-live
* Send packets with specified IP options
* Send packets with a wrong TCP/UDP checksum

## Set IP time-to-live

Nmap options include `--ttl VALUE` to set the TTL to a custom value. This option might be useful if you think the 
default TTL exposes the port scanning activities.

    nmap -sS -Pn --ttl 81 -F MACHINE_IP

## Send packets with specified IP options

Nmap allows for controlling the value set in the IP Options field using `--ip-options HEX_STRING`, where the `hex` 
string can specify the bytes you want to use to fill in the IP Options field. Each byte is written as `\xHH`, where 
`HH` represents two hexadecimal digits, i.e., one byte.

A shortcut provided by Nmap is using the letters to make your requests:

* `R` to record-route.
* `T` to record-timestamp.
* `U` to record-route and record-timestamp.
* `L` for loose source routing and needs to be followed by a list of IP addresses separated by space.
* `S` for strict source routing and needs to be followed by a list of IP addresses separated by space.

The [loose and strict source routing](../netsec/route.md) can be helpful if you want to try to make your packets 
take a particular route to avoid a specific security system.

## Send packets with a wrong TCP/UDP checksum

Another trick is to send packets with an intentionally wrong checksum. Some systems would drop a packet with a bad 
checksum, while others will not. You can use this to your advantage to discover more about the systems in your network. 
All you need to do is add the option `--badsum` to the Nmap command.

    nmap -sS -Pn --badsum -F MACHINE_IP
