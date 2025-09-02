# Entity, assets and adversaries

Tucked into the rolling hills and mushroom-shaped spires of [Fungolia](https://broomstick.tymyrddin.dev/posts/fungolia/), Openhands International is the non-governmental organisation that never sleeps—because its staff are too busy chasing human rights violations, digital injustices, and the occasional Wi-Fi gremlin. With offices in a converted subterranean library (hence the labyrinthine local area network), the team coordinates aid, advocacy, and awareness campaigns across the country's uneven digital terrain.

The organisation prides itself on its "roots in the soil, eyes on the sky" approach: deeply connected to local communities, while also monitoring international networks for threats to freedom of expression. Its servers hum quietly in the basement, holding a treasure trove of volunteer data, reports, and communications, all of which are perfectly simulated for laboratory exploration. From cloud collaboration tools to a patchwork of Internet of Things devices scattered across the office, every corner of Openhands is a potential learning ground for those brave enough to explore Earthworks.

Despite its noble mission, the non-governmental organisation is blissfully under-resourced, meaning staff devices are often outdated, passwords are reused across systems, and virtual private network certificates occasionally expire—making it a fertile playground for understanding security, misconfigurations, and chained attacks, safely in a controlled laboratory environment.

## Mission

Protecting human rights, advocating for freedom of expression, and providing emergency digital support for vulnerable communities worldwide.

## Assets

* Web Infrastructure: A public-facing WordPress site with multiple subdomains for projects, donations, and news.
* Internal Systems: Simulated staff email accounts, document repositories (Google Drive/Nextcloud style), and collaboration tools.
* Networks: A small office local area network with virtual private network access for remote staff, Wi-Fi networks, and a simulated cloud environment hosting internal applications.
* Devices: Staff laptops, mobile devices, and Internet of Things-style office devices (printers, cameras, sensors).
* Sensitive Data: Dummy volunteer records, donation transactions, human rights reports—all filled with realistic but fake data.
* Security Posture: Basic firewall rules, outdated software, and typical misconfigurations you would expect in a small non-governmental organisation.

## Adversaries

1. Automated Scanners And Bots

   * Description: Malicious scripts scanning public web servers for open ports, vulnerable plugins, or outdated services.
   * Likelihood: High
   * Laboratory Use: Reconnaissance exercises, logging, detection, and mitigation practices.

2. Script Kiddies / Opportunistic Hackers

   * Description: Amateur attackers exploiting weak passwords, misconfigured firewalls, or outdated plugins.
   * Likelihood: High
   * Laboratory Use: Brute-force attacks, web application exploitation, initial access simulations.

3. Insider Network Misconfigurations

   * Description: Staff or volunteers accidentally misconfigure virtual private networks, firewalls, or local area network devices.
   * Likelihood: Medium-High
   * Laboratory Use: Privilege escalation, lateral movement, and policy review exercises.

4. Misconfigured Or Outdated Internet Of Things Devices

   * Description: Networked printers, cameras, or Internet of Things devices acting as footholds for attackers.
   * Likelihood: Medium
   * Laboratory Use: Endpoint exploitation, network reconnaissance, device hardening.

5. APT-style Network Attacks

   * Description: Highly skilled actors targeting VPNs, cloud systems, or routing paths to intercept sensitive communications.
   * Likelihood: Medium
   * Rationale: NGOs handling human rights data are frequent targets of nation-state intelligence actors, particularly if they operate internationally.
   * Lab Use: Indirect route manipulation, cloud compromise simulations, multi-step network exercises.

6. Organised Cyber Criminals

   * Description: Skilled attackers targeting internal network traffic, virtual private network access, or cloud systems to exfiltrate data.
   * Likelihood: Medium
   * Laboratory Use: Multi-stage chained attacks: virtual private network compromise → local area network pivot → cloud access.
