# Entity, assets and adversaries

Nestled among the bioluminescent fungi and spiraling mushroom towers of Fungolia, *FungusFiber Internet* is the regional ISP that both powers the nation’s connectivity and occasionally trips over its own Ethernet cables. The offices occupy a partially hollowed-out mycelium network, with servers literally embedded in the fungal walls, humming quietly as they route packets across the land.

The team prides itself on its “spores in the air, cables in the ground” philosophy: distributing IP blocks, managing local routing, and keeping Fungolia online—mostly. From BGP routers mounted on tree trunks to cloud DNS instances hosted in cavernous server closets, every corner of *FungusFiber* offers a playground for those brave enough to explore Earthworks-style labs.

Despite its ambition, the ISP is blissfully chaotic: outdated firmware, mislabelled switches, and patchy MPLS configurations abound—making it perfect for practicing network attacks, route manipulation, and protocol mischief in a controlled lab environment.

## Mission

Providing IP address allocations, routing coordination, and internet connectivity throughout Fungolia—while making sure no packet gets lost in the bioluminescent undergrowth.

## Assets

* Routing Infrastructure: Simulated BGP/MP-BGP routers, some configured with quirky policies, others with intentional route leaks.
* Web Portal: Public IP management interface, customer dashboards, and registration forms.
* Internal Systems: Staff email accounts, network configuration files, and ticketing systems.
* Networks: Core routing lab, regional LANs, MPLS-like simulation, and Wi-Fi access points for “customers” (simulated).
* Devices: Network switches, routers, firewalls, test laptops, and spore-powered IoT sensors.
* Sensitive Data: Customer records, IP block allocations, internal config notes—all entirely fake.
* Security Posture: Mixed firmware versions, open management ports, misconfigured ACLs, and intentionally exposed routing tables.

## Adversaries

1. Automated Scanners and Bots

   * Description: Malicious scripts probing exposed BGP sessions, public management portals, and poorly protected routers.
   * Likelihood: High
   * Lab Use: Recon, detection, and logging exercises.

2. Script Kiddies / Opportunistic Hackers

   * Description: Attackers exploiting weak SNMP passwords, default router credentials, or misconfigured access lists.
   * Likelihood: High
   * Lab Use: Brute-force attempts, simple BGP session hijack simulations.

3. APT-style Network Attacks

   * Description: Nation-state or highly skilled actors manipulating BGP/MP-BGP sessions, intercepting traffic, or attempting route leaks.
   * Likelihood: Medium-High
   * Rationale: ISPs are critical infrastructure. Even small regional providers are attractive for surveillance, MITM attacks, or upstream route manipulation.
   * Lab Use: BGP/MP-BGP hijack simulations, route manipulation, advanced chained attack exercises.

4. Insider Misconfigurations

   * Description: Staff accidentally misroute prefixes, leak route maps, or misconfigure ACLs.
   * Likelihood: Medium-High
   * Lab Use: Privilege escalation, chained routing errors, and policy testing.

5. Misconfigured IoT / Network Devices

   * Description: Test sensors, monitoring probes, or old switches acting as footholds for attackers.
   * Likelihood: Medium
   * Lab Use: Endpoint exploitation, lateral movement, lab reconnaissance.

6. Organized Cyber Criminals

   * Description: Actors attempting multi-step attacks to manipulate routing tables or intercept lab traffic.
   * Likelihood: Medium
   * Lab Use: Multi-stage chain: router misconfiguration → MPLS pivot → internal network exploration.

