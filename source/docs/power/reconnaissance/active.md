# Active reconnaissance

Poking gently, very gently, with maximum caution.

Passive reconnaissance tells you what you can learn by watching. Eventually, you need to actively probe systems to learn more. This is where OT security testing requires a completely different mindset than IT security testing.

In IT, active reconnaissance means running nmap, firing up Nessus, launching web application scanners. Speed is good. 
Thoroughness is good. If something crashes, you restart it and note the vulnerability.

In OT, active reconnaissance means sending packets at speeds that would make a sloth impatient, carefully crafting 
each probe, and treating every unexpected response as potentially catastrophic. If something crashes, you have 
potentially shut down a turbine, crashed a PLC controlling dangerous processes, or triggered a safety shutdown that 
halts production and requires manual intervention to restart.

The fundamental principle of OT active reconnaissance is simple: slow is smooth, smooth is safe.

## Timing considerations (slow is smooth, smooth is safe)

OT devices were not designed to handle security scanning traffic patterns. They were designed for predictable, 
periodic, legitimate control traffic from known sources.

### Why speed matters in OT

PLCs have limited processing power compared to IT systems. A modern IT server can handle millions of packets per 
second without breaking a sweat. A PLC might scan its control program every 10-50 milliseconds, and network 
processing competes with control program execution for those precious CPU cycles.

Real-time requirements are non-negotiable. PLCs must meet real-time deadlines. If they're busy processing your 
scan packets, they might miss sensor readings or delay control outputs. In a turbine control system, a few 
milliseconds delay in responding to overspeed conditions could mean the difference between a controlled 
shutdown and mechanical damage.

State machines are common in PLC logic. Unexpected traffic can sometimes cause state transitions or confusion, 
particularly in poorly written PLC programs (which are more common than anyone likes to admit).

Limited network buffers are typical in industrial devices. They often have small network buffers because they 
expect low, predictable traffic volumes. Rapid traffic can cause buffer overflows, dropped packets, or in worst cases, 
crashes.

No concept of "scan traffic" exists in OT devices. IT systems expect to be scanned, tested, and probed. It's part 
of the threat model. OT devices expect only legitimate control traffic following predictable patterns. Scan traffic 
is entirely foreign to their design assumptions.

### The consequences of going too fast

At UU P&L, before the current testing engagement, a previous IT security consultant (who shall remain nameless, 
but definitely exists in the university's "never hire again" list) ran `nmap -A -T5` against the turbine control 
network.

What happened next was a cascade of unfortunate events:

- Turbine PLC 2 became unresponsive within 30 seconds of the scan starting
- SCADA lost communication with the PLC
- The PLC's watchdog timer expired (it had stopped responding to anything)
- Turbine entered safe shutdown mode as designed
- Power output from that turbine dropped to zero
- City experienced minor brownout as other turbines ramped up to compensate
- Alarms went off in the control room
- Operators scrambled to understand what was happening
- PLC required manual restart after 15 minutes of troubleshooting
- Investigation eventually traced the timing to the security scan
- Consultant was politely but firmly asked to leave and not return
- Security testing at UU P&L was banned for three years
- Current testing only approved after extensive negotiation and detailed test plan

This incident is why UU P&L's current policy requires passive reconnaissance first, very slow active reconnaissance 
second, and written approval for each significant test activity.

### How slow is slow enough?

The answer is frustratingly vague: it depends. It depends on the devices, the network, the current load, the 
phase of the moon, and whether the Bursar has had their morning coffee.

General guidelines for packet timing:

Minimum packet interval: 1-5 seconds between packets to the same device. This gives the device time to process each 
packet completely before the next arrives.

[Nmap](https://nmap.org/) is the standard tool for port scanning. For OT, use it with extreme timing restrictions 
and careful planning. Its timing templates translate to OT as follows:

- T0 (Paranoid): 5 minutes between probes. Serial scanning only (one port at a time, one host at a time). Originally designed for IDS evasion, perfect for sensitive OT devices.
- T1 (Sneaky): 15 seconds between probes. Serial scanning. Also designed for IDS evasion, appropriate for OT.
- T2 (Polite): 0.4 seconds between probes. Reduces bandwidth usage and target load. The fastest you should consider for OT, and only after testing.
- T3 (Normal): Default timing if you don't specify. Parallel scanning, fast probes. Fine for IT, dangerous for OT.
- T4 (Aggressive): Faster timing, assumes fast modern network. Never use in OT.
- T5 (Insane): Fastest possible timing. Accuracy sacrificed for speed. Absolutely never use in OT unless you enjoy explaining to the Archchancellor why the turbines stopped.

For OT, start with T0 or T1. Only progress to T2 after careful testing on non-critical systems. Never use T3 or higher on production OT systems.

Parallel connections should be limited to 1-2 simultaneous connections per device. Don't scan multiple devices 
simultaneously until you've verified individual scans are safe.

Protocol-specific rates vary by tolerance:
- HTTP/HTTPS web interfaces: Relatively tolerant, can use near-normal speeds
- Modbus TCP: Moderate tolerance, keep queries slow
- S7comm: Lower tolerance, very slow queries
- Proprietary protocols: Unknown tolerance, extremely slow and cautious

### Staged approach to speed

Don't start at the fastest speed you think is safe. Stage your approach:

1. One packet, one device, observe response carefully. Wait 5-10 minutes, verify no adverse effects on the device or the systems it controls.
2. Series of packets, one device, slowest timing (T0/T1). Monitor device response and system health throughout.
3. If Stage 2 successful with no issues, cautiously increase speed to T2 on the same test device.
4. If T2 successful on test device, carefully extend to other devices of the same type and model.
5. Different device types require repeating Stage 1-3. Never assume timing safe on one device type applies to others.

At UU P&L, testing turbine PLCs followed this painful but necessary progression:

- Stage 1: Single ping to PLC 3 (which was offline for scheduled maintenance)
- Waited 30 minutes, verified no issues with the offline PLC
- Stage 2: Port scan of PLC 3 with `nmap -T0`
- Took 6 hours for a comprehensive scan of common ports, but no adverse effects
- Stage 3: Repeated scan with `nmap -T1` on same offline PLC
- Completed in 45 minutes, still no issues
- Stage 4: Very carefully tested PLC 1 (online, controlling active turbine) with `nmap -T1` during low-load period at 03:00
- Success, no operational impact observed
- Stage 5: Reactor PLCs (different manufacturer, different model) restarted from Stage 1 with same cautious approach

This extreme caution seems excessive by IT standards. It is excessive, by IT standards. But it's appropriate for OT 
where the cost of "oops" is measured in millions of euros, potential safety incidents, and the Archchancellor's 
extreme displeasure. 

## Scanning

### Basic OT scanning commands

Initial gentle scan of specific industrial protocol ports:
```bash
nmap -T0 -p 80,102,502,44818 192.168.10.10
```

This scans only specific ports (HTTP, S7comm, Modbus, EtherNet/IP) at the slowest timing. Takes approximately 20 minutes to scan four ports on one IP address. This seems ridiculous. It is ridiculous. It's also necessary.

Slightly more comprehensive scan:
```bash
nmap -T1 -p 1-1024 --max-retries 1 192.168.10.10
```

Scans common ports at sneaky timing with minimal retries to reduce packet count. Takes approximately 4 hours. 
Bring a book. Bring several books.

Service identification (use with caution):
```bash
nmap -T1 -p 80,102,502 -sV --version-intensity 2 192.168.10.10
```

Attempts service version detection at low intensity. Higher intensity sends more probes, which increases risk. 
Always start with intensity 2, never go above 5 in OT.

### What not to do

Never use aggressive scans:
```bash
# DON'T DO THIS IN OT
nmap -A -T4 192.168.10.0/24
```

This aggressive scan with OS detection and default scripts will almost certainly cause problems. The `-A` flag enables OS detection, version detection, script scanning, and traceroute. All of these are invasive. The `-T4` timing is far too fast. This command is fine in IT environments. In OT, it's a resignation letter written in packet captures.

Never use vulnerability scanning scripts without extensive testing:
```bash
# DANGEROUS IN OT
nmap --script vuln 192.168.10.10
```

These scripts actively exploit vulnerabilities to verify them. Exploiting vulnerabilities on production PLCs to prove they're vulnerable is like testing if a gas tank is full by striking a match near it. Technically effective, catastrophically inadvisable.

Never scan entire subnets without careful planning:
```bash
# REQUIRES EXTENSIVE PLANNING
nmap -T0 192.168.10.0/24
```

Even at T0 timing, scanning 254 addresses takes enormous time and generates sustained traffic. This needs to be scheduled, coordinated, and carefully monitored. It's not something you do on a whim because you're curious what else is on the network.

### Industrial-specific scanners

[plcscan](https://github.com/meeas/plcscan) is a tool specifically designed to scan for PLCs using industrial protocols. It's gentler than general-purpose scanners because it was designed with industrial devices in mind.

Usage:
```bash
plcscan 192.168.10.0/24
```

This identifies Siemens, Modicon, Allen-Bradley, and other PLCs by sending protocol-specific probes. It's still not risk-free (no active scanning is), but it's more targeted and less likely to confuse devices than generic port scanning.

[s7scan](https://github.com/klsecservices/s7scan) is specifically for Siemens S7 PLCs:

```bash
python s7scan.py 192.168.30.10
```

This enumerates S7 PLC information including CPU type, module names, and firmware version. It uses the legitimate S7comm protocol, so it appears to the PLC like normal engineering access (which means it's less likely to cause issues, but also means you should still use it carefully).

These tools are designed for OT, but "designed for OT" doesn't mean "completely safe". Use them carefully, test on non-critical systems first, and monitor for adverse effects.

### At UU P&L, scanning results

Turbine PLC 1 (192.168.10.10) scanned with `nmap -T1 -p 1-1024`:
```
PORT      STATE SERVICE
80/tcp    open  http
102/tcp   open  iso-tsap
502/tcp   open  mbap
```

This revealed:
- Port 102: S7comm protocol (confirms Siemens PLC)
- Port 502: Modbus gateway (probably for third-party integration)
- Port 80: Web interface (newer Siemens PLCs have built-in web servers)

Further service detection with `nmap -T1 -p 80,102,502 -sV --version-intensity 2` revealed:
- HTTP: Siemens S7-315 web interface
- S7comm: CPU 315-2 PN/DP, Firmware V3.2.6
- Modbus: Gateway translating Modbus requests to S7comm

All this from very slow, careful scanning that took hours but caused no operational issues. The turbine kept spinning, 
the city kept having power, and the Archchancellor remained blissfully unaware that security testing was occurring.

## Banner grabbing from HMIs and web interfaces

Many HMIs and industrial devices offer web interfaces for diagnostics and configuration. These are relatively safe to interact with using standard web tools because HTTP servers are generally more robust than PLC network stacks.

### HTTP banner grabbing

Simple HTTP request reveals server information without any fancy tools:

```bash
curl -I http://192.168.10.10
```

Response might show:
```
HTTP/1.1 200 OK
Server: Siemens, SIMATIC S7
Content-Type: text/html
Date: Tue, 15 Apr 2025 03:45:12 GMT
```

This identifies the device type and manufacturer without any risky protocol interactions. It is the equivalent of 
reading a nameplate on a door rather than picking the lock.

You can also use netcat for manual interaction. The timeout (`-w`) saves from staring at a blinking cursor while the 
device thinks about life.

```bash
printf "GET / HTTP/1.0\r\n\r\n" | nc -w 3 192.168.10.10 80
```

This sends a basic HTTP request and shows the full response including headers. Sometimes servers leak information 
in custom headers or error messages that automated tools might miss.

### Web interface exploration

Modern PLCs, HMIs, and SCADA systems often have web interfaces for diagnostics and configuration. These can be explored relatively safely:

Screenshots capture login pages, diagnostic pages, and status displays. These often reveal model information, firmware versions, and configuration details without requiring authentication.

Source code examination reveals treasures. View HTML source of web pages. JavaScript and comments often contain useful information including API endpoints, default credentials (yes, really, developers leave these in comments), internal IP addresses, version information, and sometimes entire configuration objects.

Common paths are worth checking: `/admin`, `/config`, `/system`, `/diagnostics`, `/api`, `/cgi-bin`. Many industrial web interfaces use predictable URL structures.

At UU P&L, exploring the SCADA server web interface at http://192.168.20.5:

The login page source code contained this gem:

```html
<!-- Wonderware InTouch 2014 R2 SP1 -->
<!-- Build 4523, 2015-03-15 -->
<!-- Default credentials: admin/admin -->
<!-- TODO: Remove this comment before production -->
```

The comment was from 2009. The system went to production with the comment intact. The default credentials still worked. 
This is not uncommon. Developers leave comments as reminders, the system goes live, and the comments remain for years 
or decades.

The HMI web interface revealed even more through its JavaScript:

```javascript
var apiEndpoint = "http://192.168.20.5:8080/api/v1/";
var defaultUser = "operator";
var encryptionKey = "1234567890ABCDEF"; // XOR encryption key
```

This revealed an undocumented API, a default username, and the "encryption" method used for passwords (`XOR` with a 
fixed key, which is not encryption, it's obscurity wearing an encryption costume).

## SNMP enumeration (when it exists)

[SNMP (Simple Network Management Protocol)](https://snmp.com/) is occasionally found on industrial devices, 
particularly network equipment and more intelligent field devices.

### SNMP basics

SNMP comes in three versions:
- SNMPv1 and v2c: Use community strings (essentially passwords). Often default to "public" (read-only) and "private" (read-write).
- SNMPv3: More secure with proper authentication. Rarely seen in older OT deployments because it's more complex to configure.

SNMP provides access to a Management Information Base (MIB), which is essentially a hierarchical database of device information and configuration parameters.

### SNMP scanning

Test for SNMP presence:
```bash
nmap -sU -p 161 192.168.10.0/24
```

This is a UDP scan for SNMP port 161. UDP scanning is inherently slower than TCP (no three-way handshake for quick determination), so this takes time even with slow timing templates. Plan accordingly.

Enumerate with snmpwalk:
```bash
snmpwalk -v2c -c public 192.168.10.10
```

This walks through the entire MIB tree retrieving all available information. It can reveal device type and model, firmware version, network interfaces and IP addresses, running processes or services, system uptime, and detailed configuration information.

The `-v2c` specifies SNMPv2c (most common in OT), and `-c public` uses "public" as the community string (most common default).

### SNMP community string guessing

If "public" doesn't work, try common community strings:
- private (default read-write)
- admin, administrator
- manager
- snmp
- Vendor-specific defaults (cisco, hp, etc.)

Tools like [onesixtyone](https://github.com/trailofbits/onesixtyone) can brute-force community strings:

```bash
onesixtyone -c community_strings.txt 192.168.10.10
```

However, rapid-fire guessing can trigger rate limiting or temporarily disable SNMP on some devices. Use carefully in OT environments.

### At UU P&L, SNMP findings

SNMP was enabled on several network switches and one RTU with the community string "public" working on all of them. This revealed:

From network switches: Complete network topology, VLAN configurations, all connected devices with their MAC addresses and port assignments, switch firmware versions, configuration backup stored in MIB (yes, really).

From the RTU: Device model and firmware version, I/O module configurations, GPS coordinates (for time synchronisation, but also revealing exact physical location), communication settings, historical data including error counts.

The RTU's SNMP MIB included its GPS coordinates (latitude, longitude) to within a few metres. This wasn't sensitive information in this case (the substation location was public knowledge), but it illustrated how much information SNMP can expose. For facilities where location secrecy matters, this would be problematic.

More concerning was the network switch configuration backup in SNMP. Using the "private" community string (which was also unchanged from default), it was possible to not only read but modify switch configurations remotely via SNMP. This provided a path to network segmentation bypass, VLAN hopping, and general network chaos.

## Service identification

Beyond just finding open ports, identifying what services are running on those ports provides crucial context for understanding the system.

### Service identification methods

Banner grabbing is the simplest approach. Connect to a service and see what it announces. Many services helpfully introduce themselves: "Apache 2.4.41", "Microsoft IIS 8.5", "Siemens S7-315".

Protocol-specific probes involve sending protocol-specific commands and analysing responses. S7comm has specific handshake sequences that identify Siemens PLCs. Modbus has device identification functions (function code 43). EtherNet/IP has device identity objects.

Behaviour analysis examines how services respond to various inputs. Response timing, error messages, and supported commands reveal service identity even when banners are suppressed.

### Nmap service detection

Nmap's `-sV` flag enables service version detection:
```bash
nmap -T1 -p 80,102,502 -sV 192.168.10.10
```

This sends probes to each open port and attempts to identify the service and version. It's more invasive than simple 
port scanning but provides much more useful information.

Control intensity with `--version-intensity`:

```bash
nmap -T1 -p 80,102,502 -sV --version-intensity 2 192.168.10.10
```

### Wireshark for service identification

Connect to a service and capture the traffic in [Wireshark](https://www.wireshark.org/):

```bash
nc 192.168.10.10 502
```

Wireshark will dissect the Modbus protocol automatically, revealing device information in the protocol handshake even if you don't send any valid commands.

For encrypted or authenticated services, even the handshake reveals information. TLS certificates often contain device names, organisation information, and sometimes configuration details in Subject Alternative Names.

### At UU P&L service identification results

Service identification revealed several interesting findings that changed the understanding of the network:

Port 80 on several devices served completely different purposes:
- Turbine PLCs: Siemens diagnostic web interface for viewing PLC status
- SCADA server: Wonderware InTouch web client for remote operator access
- Historian: OSIsoft PI Vision web interface for data visualisation
- RTUs: Vendor-specific diagnostic portal with JSON API

Port 22 (SSH) appeared on several unexpected devices:
- Network switches: Cisco IOS SSH (expected)
- Protocol gateways: Embedded Linux (concerning, potentially vulnerable)
- One mysterious device at 192.168.40.25: Raspbian (Raspberry Pi!)

The Raspberry Pi discovery was particularly interesting. Further investigation revealed it was running a custom Python script that bridged between Modbus and a legacy serial protocol that one obscure pump controller understood. An engineer had built it years ago as a "temporary solution" to integrate the pump controller into the SCADA system. It was still running, still critical to operations, still undocumented in any official records.

This is frighteningly common in OT environments. Temporary solutions become permanent infrastructure, custom scripts become critical dependencies, and Raspberry Pis running in production become load-bearing components of multi-million euro facilities.

## Firmware version detection

Knowing firmware versions is critical for identifying known vulnerabilities and assessing risk accurately.

### Where firmware versions appear

Web interfaces often display firmware versions prominently on login pages, about pages, or system information pages. This is the easiest and least risky source.

Protocol handshakes in many industrial protocols exchange version information during connection setup. S7comm, EtherNet/IP, and some Modbus implementations include version information.

SNMP MIBs often contain firmware version in system description fields or vendor-specific MIB branches.

Banner grabs from some services announce firmware versions in their banners.

Configuration files and backups (if accessible) include version information and sometimes build dates.

### Extracting firmware versions

From web interfaces:

```bash
curl -s http://192.168.10.10 | grep -i version
```

This simple command often extracts version information from HTML without needing to manually browse.

From S7comm using s7scan:

```bash
python s7scan.py 192.168.30.10
```

Output shows:

```
Module: S7-315-2 PN/DP
Firmware: V3.2.6
Hardware: 6ES7 315-2EH14-0AB0
```

From Modbus using protocol queries:

```python
from pymodbus.client import ModbusTcpClient
from pymodbus.constants import DeviceInformation

client = ModbusTcpClient(host="192.168.10.15", port=502)

if not client.connect():
    raise RuntimeError("Cannot connect")

# Read basic device identification (Function 43 / MEI 14)
response = client.read_device_information(
    read_code=DeviceInformation.BASIC
)

if response.isError():
    print("Device does not support Read Device Identification")
else:
    # Unresolved attribute reference 'information' for class 'ModbusPDU' is a type‑hint / 
    # static analysis issue, not a protocol or code issue.
    for obj_id, value in response.information.items():
        print(f"{obj_id}: {value}")

client.close()
```

Some Modbus devices support function code 43 (Read Device Identification) which returns vendor name, product code, 
and version information.

### Searching for known vulnerabilities

Once you know firmware versions, search for known vulnerabilities in several databases:

[ICS-CERT Advisories](https://www.cisa.gov/uscert/ics/advisories): US government database of industrial control system vulnerabilities. Searchable by vendor, product, and version.

[CVE Details](https://www.cvedetails.com/): Comprehensive CVE database. Search by product name and version.

Vendor security bulletins on manufacturer websites often provide security advisories specific to their products.

[Exploit-DB](https://www.exploit-db.com/): Contains proof-of-concept exploits for known vulnerabilities. Useful for understanding exploitability, not for actually exploiting production systems.

### At UU P&L firmware version findings

Firmware version detection revealed a landscape of outdated, vulnerable systems:

Turbine PLCs running Siemens S7-315 firmware V3.2.6. Search of ICS-CERT found multiple advisories:

- [CVE-2019-13945](https://euvd.enisa.europa.eu/vulnerability/CVE-2019-13945/): Authentication bypass allowing unauthorised program uploads
- [CVE-2019-13946](https://euvd.enisa.europa.eu/vulnerability/CVE-2019-13946/): Denial of service via malformed packets
- [CVE-2020-15782](https://euvd.enisa.europa.eu/vulnerability/CVE-2020-15782/): Insufficient verification of data authenticity
- Several others

SCADA server running Wonderware InTouch 2014 R2 SP1. Multiple known vulnerabilities:

- [CVE-2020-7491](https://euvd.enisa.europa.eu/vulnerability/CVE-2020-7491): Directory traversal allowing arbitrary file read
- [CVE-2020-7492](https://euvd.enisa.europa.eu/vulnerability/CVE-2020-7492): Authentication bypass in web interface
- [CVE-2021-27040](https://euvd.enisa.europa.eu/vulnerability/CVE-2021-27040): Remote code execution via crafted packets

Historian running OSIsoft PI Server 2015. Known vulnerabilities:

- [CVE-2018-8002](https://euvd.enisa.europa.eu/vulnerability/CVE-2018-8002): Denial of Service via crafted pdf content
- [CVE-2019-6543](https://euvd.enisa.europa.eu/vulnerability/CVE-2019-6543): SQL injection via PI Server web interface search functionality, potentially exposing or modifying historian data
- [CVE-2020-10611](https://euvd.enisa.europa.eu/vulnerability/CVE-2020-10611): Authentication bypass in PI Server allowing unauthorised access to restricted functions

None of these systems were patched because "patching might break things". The security team's job is not to immediately 
demand patching. It is to document the vulnerabilities, assess the actual risk in context (considering network 
segmentation, access controls, and other mitigating factors), and recommend appropriate action (which might be 
patching, might be compensating controls, or might be accepting the risk).

## Engineering workstation discovery

Engineering workstations are high-value targets in OT security. They have legitimate access to program PLCs, modify 
SCADA configurations, and often bridge between corporate and OT networks. Finding them is important.

### Identifying engineering workstations

Network behaviour patterns reveal engineering workstations:

- Connect to many different PLCs
- Transfer large amounts of data (uploading/downloading programs)
- Connect sporadically rather than constantly (unlike SCADA which polls continuously)
- Often connect during specific times (weekday business hours, maintenance windows)

Open services indicate engineering workstations:

- RDP (port 3389) for remote access
- VNC (port 5900) for remote control
- File sharing (port 445, SMB) for transferring files
- Engineering software-specific ports (TIA Portal uses various ports, RSLogix has specific ports)

Hostnames are often descriptive:

- `ENG-WS-01`, `ENGINEERING-LAPTOP`, `PLC-PROGRAMMER`
- `JOHN-ENGINEERING` (personal workstations)
- Sometimes just `LAPTOP-ABC123` (generic Windows hostnames)

Web browsing activity (if proxy logs are available) shows engineering workstations accessing vendor support websites, documentation sites, software download portals.

### Discovery methods

Passive observation is safest. Watch for devices that connect to PLCs for programming activities (uploads/downloads taking several seconds to minutes). Note their IP and MAC addresses.

Active scanning looks for typical engineering workstation services:

```bash
nmap -T1 -p 3389,5900,445,102,502 192.168.40.0/24
```

This scans for RDP, VNC, SMB, and industrial protocols on the engineering network.

ARP cache inspection on network devices may show engineering workstations that bridge networks (they appear in ARP caches of devices on multiple VLANs).

### At UU P&L engineering workstation findings

Engineering workstations were identified through multiple indicators:

Hostname `ENG-WS-01` appeared in DHCP logs even though it currently had a static IP (it had briefly used DHCP during 
initial setup years ago, and the DHCP server still had the record).

Network behaviour showed regular connections to all turbine and reactor PLCs, not just monitoring but transferring 
kilobytes to megabytes of data (program uploads and downloads).

Open services included RDP port 3389 accessible from corporate network, SMB port 445 with anonymous access enabled 
(security through obscurity, except without the obscurity), HTTP port 80 serving a local copy of vendor documentation.

The real treasure was discovered through 
[SMB enumeration](https://red.tymyrddin.dev/docs/through/persistence/grounds/thm/relevant.html#smb-enumeration):

```bash
smbclient -L //192.168.40.15 -N
```

This listed shared folders including `PLC-Programs`, `Backups`, `Vendor-Software`, and `Documentation`. The 
`PLC-Programs` share was accessible without authentication and contained the complete program libraries for all 
turbine and reactor PLCs, including current and historical versions.

The `Vendor-Software` share contained licensed engineering software installers and, more concerning, a text file 
named `License-Keys.txt` with software license keys and activation codes.

One engineering workstation had a mapped network drive pointing to a vendor's FTP server with cached credentials. 
The FTP server was accessible without authentication and contained engineering software, configuration backups, 
and documentation for multiple customers across several industries. This wasn't UU P&L's fault, but it illustrated 
the extended attack surface when engineering workstations are compromised.

## Remote access entry points

Finding how external parties access OT systems reveals critical attack vectors and often exposes the weakest links in 
security.

### Types of remote access

Vendor VPN connections allow vendors to provide support. These can be persistent (always connected) or on-demand 
(connected only when needed). They're extremely common and often poorly secured.

Remote desktop services include RDP, VNC, TeamViewer, AnyDesk, and similar tools. Sometimes officially deployed, 
sometimes installed by individual engineers for convenience.

Web-based access through web interfaces for remote management, cloud-based SCADA platforms, vendor portals providing 
remote access to customer systems.

Dial-up modems still exist in industrial environments. Often forgotten, unmaintained, and using ancient authentication 
methods (or none at all).

Cellular routers provide connectivity for remote sites using 4G/5G networks. Convenient, often insecure.

Cloud connections to cloud-based monitoring, analytics platforms, vendor support systems.

### Discovery methods

Network scanning looks for VPN concentrators, remote access servers, and modems:

```bash
nmap -T1 -p 1723,500,4500,1194 192.168.0.0/16
```

This scans for common VPN ports (PPTP, IPSec, OpenVPN).

Configuration review of VPN configurations, remote access policies, and vendor contracts specifying remote access terms.

Firewall rules analysis shows inbound rules allowing remote access, port forwarding rules, and external access paths.

Active connections inspection shows who's currently connected remotely (check VPN logs, terminal server sessions, 
remote desktop connections).

### External reconnaissance with Shodan

[Shodan](https://www.shodan.io/) is a search engine for internet-connected devices. It continuously scans the entire 
internet and indexes what it finds, creating a searchable database of every exposed device.

Search for your organisation's IP ranges:

```
net:203.0.113.0/24
```

Search for specific industrial systems:

```
port:502 country:AM
port:102 Siemens
port:44818 Rockwell
port:47808 BACnet
```

Search for specific vulnerabilities:

```
"Authentication: disabled" port:102
"default password" port:80
```

[Censys](https://censys.io/) is similar to Shodan, providing another view of internet-exposed systems with slightly 
different indexing and search capabilities.

### At UU P&L remote access discoveries

Remote access discovery revealed a concerning landscape:

OpenVPN server on the OT network (192.168.50.10) accessible from the internet. Configuration review showed five 
vendor accounts, all sharing the same password (`vendor123`), no certificate-based authentication, no two-factor 
authentication, and logs showing successful connections from IP addresses in several countries.

TeamViewer installed on SCADA server with unattended access enabled. The password was written on a sticky note 
attached to the server (discovered during a site visit). TeamViewer ID was listed in vendor documentation that 
had been publicly posted to a support forum years ago.

Two cellular routers at remote substations discovered via Shodan search:

```
port:80 "Digi" country:AM
```

These routers had web interfaces exposed to the internet with default admin credentials still working 
(`admin`/`admin`). Port forwarding rules allowed direct access to substation RTUs from the internet on Modbus 
TCP port 502. Anyone who found these routers (trivial with Shodan) could send Modbus commands directly to 
substation equipment.

An old dial-up modem on the reactor control network was discovered in documentation. The phone number was listed in 
an archived maintenance manual. Calling the number, the modem answered with a Hayes-compatible carrier tone. 
Connecting with a serial terminal, it presented a login prompt that accepted default credentials from the 
modem manufacturer's documentation (still available online).

This modem had been installed in 1994 for vendor remote access. The vendor contract had ended in 2003. The 
modem was never disconnected. It had been sitting there for 23 years, faithfully answering calls, providing 
unauthenticated access to the reactor control network to anyone with a phone line and a serial terminal emulator.

The recommendations following remote access discovery were extensive and sobering. For the vendor VPN, implement 
certificate-based authentication, disable shared accounts, enable two-factor authentication, implement IP 
whitelisting to only allow connections from known vendor addresses, and establish regular access reviews. For the 
cellular routers, change default credentials immediately, disable management interfaces from internet access, 
implement VPN for all remote connections, and require security approval before deploying any internet-connected 
devices. For the dial-up modem, disconnect it. Immediately. There's no scenario where a 23-year-old modem with no 
authentication on a reactor control network is acceptable.

The cellular routers discovered via Shodan were particularly concerning because they provided direct internet 
access to operational substation equipment with nothing more than default credentials protecting them. This is 
the sort of finding that makes security assessors wake up at 3 AM wondering if they should have been more emphatic 
in their recommendations.

It's also distressingly common. Field technicians deploy equipment for operational convenience without security 
oversight. The equipment works reliably, fades into background infrastructure, and nobody remembers to audit it 
until a security assessment years later reveals it to the world via Shodan.

Active reconnaissance at UU P&L revealed a landscape ranging from concerning to terrifying. But it was done slowly, 
carefully, and without causing operational disruptions. The turbines kept spinning, the reactor stayed contained, 
the Librarian remained comfortable, and most importantly, nobody had to explain anything awkward to 
[the Patrician](https://indigo.tymyrddin.dev/docs/vetinari/).

That's success in OT security testing.

