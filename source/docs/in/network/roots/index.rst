Rootways of the World Tree (@Internet)
=========================================

In the intricate network of the internet, BGP and MP-BGP serve as the deep-rooted pathways, connecting diverse
networks across the digital landscape. These protocols, while essential for data routing, are susceptible to various
vulnerabilities. Through direct manipulations like prefix hijacking and indirect exploits via other protocols, these
roots can be compromised, leading to potential disruptions.

.. toctree::
   :glob:
   :maxdepth: 2
   :includehidden:
   :caption: Branching far and wide

   tcp/index
   ip/index
   bgp/index
   icmp/index
   dns/index
   ipsec/index
   bgpsec/index

Why is hacking BGP so attractive for nation state hackers?
===================================================================
Because BGP is the rickety Victorian plumbing of the internet — still doing the job, but full of leaky joints, no authentication by default,
and everyone pretending it is fine until the pipes burst. It can give:

1. Global control with local action: With one bad advertisement, you can reroute huge swathes of internet traffic. A single ISP fat-fingering (or a state actor deliberately injecting) a prefix hijack can drag banking, comms, or government traffic through your chosen path. Instant man-in-the-middle at internet scale.
2. Weak authentication: BGP was built in a world where ISPs all “trusted each other” (cue laughter). There is no native, strong cryptographic verification of route announcements. RPKI and BGPsec exist but are patchy, uneven, and often optional. Attackers thrive in that gap.
3. Plausible deniability: BGP “oopsies” happen all the time. If a nation state wants to reroute EU traffic through Moscow for an hour, they can always blame “misconfiguration.” It muddies attribution.
4. Data interception and manipulation: Once traffic flows through your infrastructure, you can passively collect intelligence, insert malicious payloads, downgrade encryption, or just quietly observe who talks to whom. It is surveillance catnip.
5. Disruption without bombs: You can blackhole services (make them unreachable) or split-brain whole regions. Knocking out banking, cloud services, or critical infrastructure via routing games is cleaner than a cyber-kinetic strike and less likely to trigger Article 5.
6. Geopolitical leverage: States can pressure or co-opt ISPs within their borders to play along. This makes BGP manipulation easier than, say, directly hacking every target. It scales.

In short: it is global, fragile, and central to everything. You get outsized bang for your buck.
