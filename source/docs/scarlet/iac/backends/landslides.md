# Landslides

A short tour of the C2s most likely to be in scope today, with notes on scriptability, network fingerprint,
telemetry, and origin. The four questions that matter operationally: can it be deployed and destroyed without
touching a UI; does it leave a unique fingerprint on the wire before the payload lands; what does it phone home
to; and who made it and where.

## Sliver

[Sliver](https://github.com/BishopFox/sliver) (BishopFox, USA) is the default open-source choice in 2026.
Implants are Go-compiled; the server supports HTTP(S), mTLS, WireGuard, and DNS; the multiplayer team server is
built in. v1.7.3 shipped February 2026 with active ongoing development.

Fully scriptable via `sliver-py`, a Python package that wraps the gRPC API. Deploy a listener, generate an
implant, manage sessions, and tear everything down without opening the console.

Network fingerprint: a known problem. The default Go TLS stack produces a catalogued JA3 hash, and Sliver's
JARM fingerprint appears in public Shodan-based hunting queries. Hunt and Hackett, Corelight, and others have
published network detection methods. Sliver can randomise cipher suites to shift the JARM, but the default is
a signal. Use [TLS mimicry](../redirectors/tls-mimicry.md) and a [C2 profile](c2-profiles.md) together; neither
alone closes the fingerprint gap.

No telemetry and no phone-home. The team server logs sessions and tasks to a local SQLite database; verbosity
is configurable. Runs fully air-gapped once the binary is on the host.

## Mythic

[Mythic](https://github.com/its-a-feature/Mythic) (USA) is modular: the framework provides the team server and
web UI; operators add agent plugins (Apollo, Athena, Poseidon, Thanatos) per platform and operating system.
v3.4.x active through early 2026.

Fully scriptable via a GraphQL API and WebSocket interface, wrapped by the `mythic` PyPI package. Payload
builds, callback management, and task dispatch are all API-driven.

Network fingerprint: no single stable fingerprint exists at the framework level. Detection requires
characterising each agent-and-profile combination separately. Kaspersky published a traffic analysis method in
2025, but the modular design means what they characterised is one configuration, not the whole framework. This
is Mythic's clearest operational advantage over the alternatives.

No telemetry and no phone-home. Logs reside in the local PostgreSQL container. The full stack runs offline
after images are pulled; no outbound connection to anything outside the operator's infrastructure.

## Havoc

[Havoc](https://github.com/HavocFramework/Havoc) (C5pider, Germany) was archived on 20 February 2026.
Development is finished. The repository is read-only; no further updates or evasion improvements are coming
from the original author. Existing deployments continue to work, and the Demon agent still appears in threat
actor toolsets in the wild, but the EDR signature coverage will only improve over time as the codebase
remains static. MITRE ATT&CK carries it as S1229; Malpedia catalogues Demon.

Worth keeping in an inventory of what defenders are hunting for. Not a reasonable selection for new operations.

Havoc was German-authored, making it one of two European-origin frameworks that made the open-source mainstream,
the other being Outflank C2 below.

## Cobalt Strike

[Cobalt Strike](https://www.cobaltstrike.com/) (Fortra, USA) is the commercial flagship and the most thoroughly
fingerprinted C2 in existence. Google has published 165 YARA rules covering 34 cracked versions; JARM and JA3
fingerprints for default team servers are public and searchable on Shodan; every major EDR vendor ships specific
Cobalt Strike detections. Operation Morpheus (2024 law enforcement action) achieved a reported 80% reduction in
publicly exposed malicious infrastructure.

Fully scriptable since version 4.12 (2025), which added a REST API alongside the existing Aggressor Script
interface. End-to-end automation via HTTP is now possible without the Aggressor DSL.

Operators depend on custom Malleable C2 profiles, sleep masking, and BOFs to evade detection. The profiles
handle traffic shaping; the underlying JARM exposure requires additional measures at the [redirector layer](../redirectors/cdn-fronting.md).
Default Beacon signatures are detected automatically by most endpoint products. A cracked version is a
liability regardless of the profile.

Telemetry: Fortra operates a licence validation server and CS contacts it on startup. Fortra can deactivate
instances remotely; Operation Morpheus demonstrated this at scale when roughly 600 cracked team servers were
killed via that channel. Licence validation is not suppressible without voiding the licence or running a cracked
copy, either of which carries its own risk. Team server logs write locally and can be restricted. The activation
channel is the opsec exposure; it originates from the team server host, not from the implant.

## Brute Ratel C4

[Brute Ratel C4](https://bruteratel.com/) (Chetan Nayak / NinjaParanoid, India) is commercial and
customer-vetted. v2.3 "Flux" (October 2025) rebuilt the Badger implant on a custom compiler; v2.4 was
announced mid-2026. EDR evasion is the primary selling point, and the author publishes evasion claims per
release tested against 17 EDRs.

A cracked copy leaked in 2022, which drove widespread vendor signatures. BRC4's JARM has been identified and
published for Shodan hunting. Still meaningfully harder to detect than default Cobalt Strike, but the gap has
narrowed as vendors caught up to the leaked version's signatures.

Scriptability is less mature than Sliver, Mythic, or Nighthawk. More manual operator interaction is expected
during setup and rotation.

Telemetry: licence activation contacts the author's servers. The author has demonstrated willingness to
remotely brick instances, including licensed customers suspected of misuse. Hardware locking was introduced in
v2.x; periodic check-ins are expected. Operational logging is local. A team server that calls out to a
licence endpoint on startup is a fixed outbound connection that appears in egress logs regardless of how
carefully the implant traffic is shaped.

## Nighthawk

[Nighthawk](https://nighthawkc2.io/) (MDSec, UK) is commercial, vetting-only, and the clearest European
option among licensed frameworks. v0.3.4 "Sivako" shipped July 2025.

Fully scriptable since v0.3 (June 2024): a JSON-RPC web service covers the full framework (team server, beacon,
artefacts), and client-side Python scripting via PythonNet is available from v0.3.3. Deploy, configure, task,
and tear down without the UI.

Network fingerprint: no public JA3/JARM catalogue comparable to Cobalt Strike or BRC4 exists. Detection tends
to be behavioural rather than signature-based, which is a direct consequence of the limited distribution
model. The hardware locking and mandatory online activation introduced in v0.3.4 are partly a response to a
prior software leak: the vetting model has been bypassed at least once.

Telemetry: mandatory online activation and hardware locking since v0.3.4 mean the team server contacts MDSec
infrastructure on startup. MDSec can deactivate licences remotely. Operational logging is local and
configurable. Same exposure as Cobalt Strike: a fixed outbound connection at startup from the server host,
independent of implant traffic.

## Outflank C2

[Outflank C2](https://www.outflank.nl/products/outflank-security-tooling/outflank-c2/) (Outflank BV,
Netherlands) launched publicly in August 2024, when the earlier Stage1 framework gained native implants for
Windows, macOS, and Linux under the new name. Commercial, subscription-based, sold to verified red teams as
part of the Outflank Security Tooling suite.

Automation is a design priority: Jupyter Notebooks that interface directly with implants ship with the
framework, not as an afterthought. OPSEC focus includes seven sleep masking methods and advanced reflective
loading.

No public JA3/JARM fingerprint catalogue has been published, consistent with its lower public profile. A Dutch
company and one of the two actively developed European C2 frameworks on this list.

Telemetry: commercial subscription with licence validation; the exact check-in behaviour is not publicly
documented. No evidence of operational telemetry beyond licence verification. Assume activation contacts
Outflank infrastructure; the precise frequency is unknown.

## Metasploit

[Metasploit](https://www.metasploit.com/) (Rapid7, USA) is the framework that defined the category. Default
signatures have been detected by every Windows endpoint product since around 2007. For Linux targets, and for
opportunistic exploitation across the full lifecycle, it can still be a workable choice. The [container setup](metasploit.md)
stays current via the Kali package feed.

No telemetry and no phone-home. Logs write to `~/.msf4/` locally. Runs fully air-gapped.

## Empire

[Empire](https://github.com/BC-SECURITY/Empire) (BC-Security, USA) is a PowerShell exploitation framework at
v6.6 (May 2026), with active ongoing development and a REST API for automation. mTLS between agents and
listeners landed in v6.3.

PowerShell tradecraft is among the most heavily monitored attack surfaces an EDR covers: Script Block Logging,
AMSI, and constrained language mode collectively reduce its effectiveness on hardened Windows 11 endpoints. The
Python and C# agents are somewhat less-detected, but Empire's network signatures are catalogued. A viable
choice for targets confirmed to be running ungoverned PowerShell estates, not a default.

No telemetry and no phone-home. Team server logs reside locally. Runs fully offline.

SilentTrinity, which used the same niche, has had no maintainer activity since 2020 and no formal releases.
It is gone.
