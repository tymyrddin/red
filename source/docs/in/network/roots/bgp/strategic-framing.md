# BGP as a strategic attack surface

BGP's appeal to state-level actors follows from its structure. It is the rickety Victorian plumbing of the internet: still doing the job, full of leaky joints, no authentication by default, and everyone pretending it is fine until the pipes burst.

The leverage is global and the action is local. A single bad advertisement can reroute traffic from banking systems, communications infrastructure, or government networks through an attacker-controlled path. One misconfigured router, man-in-the-middle at internet scale. Authentication is weak by design: BGP was built in a period when ISPs broadly trusted each other, and there is no native cryptographic verification of route announcements. RPKI and BGPsec address this, but adoption is patchy and often optional. That gap is where the attacks live.

Plausible deniability is a structural property of the protocol. BGP misconfigurations happen routinely. A state actor rerouting traffic through a controlled network for an hour can credibly attribute the incident to operator error, muddying attribution in ways that most other attack categories cannot replicate.

Once traffic flows through a controlled network, the options expand: passive intelligence collection, payload insertion, encryption downgrade, or simply observing who communicates with whom. It is surveillance catnip. Blackholing a prefix makes a service unreachable without requiring kinetic action or triggering the treaty obligations that follow from one.

States with influence over domestic ISPs can coerce or co-opt them, making BGP manipulation easier to execute than any equivalent compromise of individual targets. It scales in a way that direct intrusion does not.

Global, fragile, and central to everything.
