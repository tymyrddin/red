# Trends in evasion

Evasion has shifted from "hide the malware" to "be indistinguishable from normal
system behaviour". The techniques have not become more exotic; they have become more
disciplined. The goal is plausibility, not invisibility.

The pages in this section cover the major technique areas:

- [Living off the land](lolbins.md): chaining legitimate tools so there is nothing
  to scan and nothing to attribute
- [Fileless and memory-resident execution](fileless.md): dropping binaries on disk
  is now considered amateur
- [Bring your own vulnerable driver](byovd.md): loading a signed, trusted driver to
  disable the very tools trying to detect you
- [EDR evasion by design](edr-evasion.md): modern implants are built from the start
  to evade specific endpoint products, including adaptive behaviour per environment
- [AI-assisted polymorphism](ai-polymorphism.md): per-deployment payload mutation
  that breaks signature and static heuristic detection
- [Sandbox evasion](sandbox-evasion.md): environment awareness, sleep, trigger
  conditions, and ways to make automated analysis see nothing

The [attack chain](attack-chain.md) page maps these into the low-noise intrusion
model: how steganography, cryptographic weaknesses, and evasion techniques combine
into a coherent operational approach.

The defensive counterpart is in the blue notes: what each of these looks like from
the detection side and where the defences currently hold or fail.

## The bottom line

Modern evasion is not about being invisible. Perfect stealth is not required. What
is required is staying below the noise floor: producing less signal than the threshold
at which an analyst will act on it.

The attacker's goal is plausibility. If it looks like a user, an admin, or a normal
process, most systems pass it through. The gap between "working" and "compromised"
is now a question of whether the behaviour is normal enough, not whether it is hidden.
