# Entity, assets and adversaries

Hidden in a sprawling mycelium lab under the Fungolia capital, *MycoSec Labs* advertises itself as the region’s premier cybersecurity consultancy—but its own internal networks are a veritable playground for Earthworks exercises. Lab servers host simulated client networks, practice targets, and intentionally misconfigured environments for testing.

Their motto: “We poke, prod, and plant spores of doubt—mostly for your own good.” Staff laptops run mixed OSes, containerized lab environments abound, and test VLANs simulate clients’ internal networks, offering rich opportunities for chained network exercises.

## Mission

Offer security assessments, red-team simulations, and digital safety consultancy across Fungolia, while maintaining internal labs for research and staff training.

## Assets

* Internal Lab Networks: Simulated client LANs, VLANs, isolated cloud environments.
* Lab Devices: Laptops, routers, firewalls, IoT testbeds.
* Tools: Vulnerable virtual machines, containerized apps, fake telemetry logs.
* Data: Dummy client records, attack simulations, lab-generated logs.
* Security Posture: Deliberately mixed—some systems highly hardened, others purposefully exposed.

## Adversaries

1. Script Kiddies / Opportunistic Hackers

   * Description: Attackers exploiting exposed lab environments, deliberately misconfigured VMs, or test containers.
   * Likelihood: High – publicly visible lab nodes attract curiosity.
   * Lab Use: Brute-force login attempts, simple exploitation, test lateral movement techniques.

2. Automated Scanners / Bots

   * Description: Bots probing exposed lab services, outdated containers, or public lab portals.
   * Likelihood: High – unavoidable on any lab network with internet-facing components.
   * Lab Use: Recon, logging, and containment practice without risk to real systems.

3. APT-style Network Attacks

   * Description: Advanced actors attempting to compromise lab networks, containerized client environments, or internal routing experiments.
   * Likelihood: Medium
   * Rationale: Even labs can attract attention because they simulate real infrastructure. Skilled actors may attempt to exploit misconfigured lab systems, especially if publicly exposed.
   * Lab Use: Indirect routing manipulation, lab-to-lab network pivot, multi-step chained attacks.

4. Insider Misconfigurations

   * Description: Lab staff misconfigure VLANs, container networking, or lab-to-lab connections, creating exploitable paths.
   * Likelihood: Medium – intentional complexity of labs plus human error produces openings.
   * Lab Use: Practice privilege escalation, lateral movement, and chained lab scenarios.

5. Organized Cyber Criminals

   * Description: Actors attempting multi-stage attacks to compromise simulated clients’ networks hosted in lab environments.
   * Likelihood: Medium – labs intentionally simulate real-world exposure, attracting “skilled adversaries.”
   * Lab Use: Chained attacks: compromised lab VM → internal lab VLAN → simulated client network.

