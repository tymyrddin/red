# Landslides

A short tour of the C2s most likely to be in scope today, and the ones that built the road.

## Sliver

[Sliver](https://github.com/BishopFox/sliver) is the default open-source choice in 2026. Implants are Go-compiled,
the server supports HTTP(S), mTLS, WireGuard, and DNS, and the multiplayer team server is built in. It absorbed
the mind-share that Empire and SilentTrinity used to hold.

## Mythic

[Mythic](https://github.com/its-a-feature/Mythic) is modular: the framework provides the team server and web UI,
and operators add agent plugins (Apollo, Athena, Poseidon) per platform. Useful when the operation needs unusual
agent behaviour without rewriting a whole framework.

## Havoc

[Havoc](https://github.com/HavocFramework/Havoc) is a modern open-source framework with a Qt UI reminiscent of
Cobalt Strike. The Demon agent is C-based, with reasonably current evasion against Windows EDR.

## Cobalt Strike

[Cobalt Strike](https://www.cobaltstrike.com/) is still the commercial flagship. Beacon's malleable C2 profiles
remain the gold standard for traffic shaping. Cracked versions exist and are widely abused, which means the
default Beacon signatures are also widely detected.

## Brute Ratel and Nighthawk

[Brute Ratel C4](https://bruteratel.com/) and [Nighthawk](https://www.mdsec.co.uk/nighthawk/) are commercial
alternatives with heavy investment in EDR evasion. Both vendors vet customers, which raises the bar to obtain a
legitimate licence.

## Metasploit

For the best part of two decades the undefeated champion of C2 frameworks was the
[Metasploit](https://www.metasploit.com/) framework. The default settings have been flagged by every Windows
security product since 2007. For Linux targets, and for opportunistic exploitation across the lifecycle
(reconnaissance through post-exploitation), it is still a workable choice.

## Empire and SilentTrinity

[Empire](https://github.com/BC-SECURITY/Empire) is a PowerShell exploitation framework, and
[SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) is a Python and .NET DLR successor. Both shaped a
generation of operations against Windows. Both assume a PowerShell or AMSI environment that no longer exists by
default on hardened Windows 11 endpoints. Treat them as historical reference unless the target is genuinely
behind the times.
