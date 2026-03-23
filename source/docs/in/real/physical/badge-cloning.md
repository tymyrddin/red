# Badge cloning

Most access control badges transmit credentials wirelessly and do so to anything within range that is
polite enough to ask. The reader on the wall next to the door is not the only device that can ask.
A concealed reader in a bag, attached to a door frame, or built into something that looks like a
payment terminal can ask too, and the badge will answer regardless of who is holding the reader.

This is not a new vulnerability. RFID-based access control has been exploitable in this way for decades.
The reason it persists is that replacing an installed access control system is expensive, disruptive, and
hard to justify to a finance team unless something has demonstrably gone wrong. So most organisations
continue running the same technology they deployed fifteen or twenty years ago, and the tools required to
exploit it are available on the open market for the price of a decent restaurant meal.

## Low-frequency RFID

The most common access card technology in corporate environments is low-frequency RFID, operating at
125kHz. HID Prox cards are the archetype. These cards have no encryption and no challenge-response
authentication. They broadcast a fixed identifier to any reader that powers them up. Cloning one
requires capturing that identifier and writing it to a blank card of the same type, which takes
a few seconds with a Proxmark3 or a Flipper Zero and is not meaningfully more complicated than
copying a file from one USB drive to another.

The read range for a concealed attack varies depending on antenna size and card placement, but a few
centimetres is achievable with pocket-sized equipment, and considerably more with a reader that can
be left in a fixed position near a door or a turnstile. An attacker standing in a lift, waiting at
a reception desk, or sharing a table in a canteen can skim cards without any physical contact.

## High-frequency RFID and NFC

Cards operating at 13.56MHz, including various MIFARE variants and HID iCLASS, were intended to
be more secure. Some are. MIFARE Classic, which remains widely deployed, uses a proprietary cipher
that was broken by academic researchers in 2008. Cloning it requires capturing multiple authentication
exchanges to recover the key, but this is well within the capability of modern tools and does not
require any particular expertise.

MIFARE DESFire and HID Seos use stronger cryptography and are not practically clonable with current
consumer-grade tools. Organisations running these technologies are in a substantially better position,
though they may still be vulnerable to relay attacks if access decisions are made solely on card
presence rather than proximity verification.

## Practical skimming

The operational challenge in badge cloning is usually getting close enough to the target card. Suits,
bags, and jacket pockets all attenuate the signal, so passive skimming at distance is unreliable
without specialised equipment. Most practical attacks involve either a concealed reader worn on the body
and used in close proximity, or a fixed reader placed near a location where badges are likely to
be within range: a card-activated vending machine, a floor reader next to a lift, or a door frame
where people tap in.

Combining the skim with a distraction, whether constructed or opportunistic, reduces the window in
which someone might notice unusual proximity or equipment. It also provides cover for the physical
position that a concealed reader requires.

Once a card is cloned, the duplicate will continue to work until the organisation rotates the
credential, which most do not do on any regular schedule. A cloned badge obtained during an engagement
may remain valid for months or years, which is relevant when scoping persistence testing.

## Runbooks

- [Runbook: Physical access engagement](../runbooks/physical-entry.md) — covers badge cloning equipment and operational placement in the on-site phase
