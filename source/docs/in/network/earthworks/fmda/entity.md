# Entity, assets and adversaries

Nestled in a government complex shaped like interlocking mushrooms, the FMDA oversees all things digital in Fungolia—from spectrum allocation to IP block management and compliance monitoring. Its public portals are occasionally more exposed than intended, and internal networks are a patchwork of legacy systems, half-forgotten policies, and experimental routing labs.

The Ministry operates under the philosophy “bureaucracy underground, oversight aboveground”: policies are drafted in secretive fungal chambers while public-facing systems attempt to stay online. Servers hum beneath the spore-laden floors, hosting IP registries, compliance logs, and internal memos—all perfect fodder for Earthworks practice.

## Mission

Regulate and allocate digital resources across Fungolia, manage spectrum, IP assignments, and ensure compliance with national and international digital laws.

## Assets

* Public portals: IP assignment forms, compliance dashboards, DNS registries.
* Internal networks: LAN for policy staff, internal routing labs, legacy databases.
* Devices: Staff laptops, test routers, outdated firewalls, VLAN-segmented office networks.
* Sensitive Data: Dummy compliance records, IP block allocation tables, internal policy drafts.
* Security Posture: Partially outdated software, exposed ports, misconfigured VPNs, weak ACLs.

## Adversaries

1. Automated Scanners / Bots

   * Description: Scripts probing public portals, IP registries, and exposed BGP/DNS servers for misconfigurations or outdated software.
   * Likelihood: High – public-facing government systems attract constant automated attention.
   * Lab Use: Recon exercises, detection, logging, and simulating early-stage intrusions.

2. Script Kiddies / Opportunistic Hackers

   * Description: Amateur attackers exploiting weak VPN credentials, exposed admin interfaces, or misconfigured routing ACLs.
   * Likelihood: High – FMDA’s partially exposed networks make it an attractive target for curious attackers.
   * Lab Use: Brute-force attacks, web portal exploitation, privilege escalation on internal services.

3. APT-style Network Attacks

   * Description: Sophisticated attackers targeting internal administrative networks, IP registries, or routing layers.
   * Likelihood: Medium-High
   * Rationale: Government digital infrastructure is always an attractive target for espionage or political leverage. Public portals may be lightly protected, creating realistic attack surfaces for labs.
   * Lab Use: Internal network pivoting, BGP route capture, multi-stage lab attack exercises.

4. Insider Misconfigurations

   * Description: Staff unintentionally misconfigure routing, ACLs, or VPN access, opening internal networks for lateral movement.
   * Likelihood: Medium-High – complex internal networks + bureaucratic processes increase human error.
   * Lab Use: Test privilege escalation, route misconfigurations, chained network misuses.

5. Organized Cyber Criminals

   * Description: Skilled actors attempting to manipulate IP allocations, exfiltrate compliance records, or intercept administrative traffic.
   * Likelihood: Medium – FMDA may be targeted for operational intelligence or political gain.
   * Lab Use: Simulate chained attacks through VPN → internal LAN → BGP/routing layers.

