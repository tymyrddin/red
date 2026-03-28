# Physical lures and planted devices

Not every physical social engineering technique requires being present at the target. Some of the most
effective attacks involve leaving something behind and waiting for a target to interact with it
voluntarily. The psychology here is curiosity, helpfulness, and the low perceived cost of what appears
to be an innocuous action.

The planted device or document travels from the attacker to the target through ordinary human behaviour.
Someone finds a USB drive and wonders what's on it. Someone picks up a document from a printer and
reads it. Someone scans a QR code on a poster because they want the Wi-Fi password. None of these
actions feels like a security decision, which is precisely why they work.

## USB drops

A USB drive left in a car park, a reception area, a canteen, or on a desk communicates two things to
the person who finds it: someone lost this, and it might contain something interesting. Studies have
consistently found that a substantial proportion of found USB drives get plugged into a computer,
often within minutes of being found. The "just checking if it has a name on it" justification does
not require much encouragement.

The drive itself can be configured to execute a payload automatically on connection, to present as a
keyboard and type commands, or to simply drop a file that the user opens themselves. The Rubber Ducky
and the Bash Bunny from Hak5 are purpose-built tools for the keyboard injection approach: they
identify as human interface devices rather than storage, bypassing policies that block unknown USB
storage, and execute a preprogrammed keystroke sequence in a few seconds.

Labelling drives increases the interaction rate considerably. A drive labelled "Q3 Salary Review"
or "Redundancy List 2025" disappears into a computer almost immediately. The label creates a reason
to look that overrides whatever cautious instinct might otherwise apply.

## QR code stickers

A QR code is a URL encoded in a way that humans cannot read and most security tools cannot intercept.
It is designed to be scanned, and people scan them without thinking, because QR codes have been
normalised as a convenience mechanism for accessing Wi-Fi, menus, and payment systems. The URL
encoded in the QR code is invisible until after the scan, at which point the phone has already
made a network request.

Stickers placed over legitimate QR codes in office environments redirect scans to attacker-controlled
destinations. Car park payment machines, meeting room booking systems, visitor Wi-Fi access points,
and printed materials with QR codes are all viable placements. A sticker can be produced cheaply,
applied in seconds, and may go undetected for weeks.

The destination can be a credential harvesting page, a page that triggers a browser exploit, or
simply a tracking pixel that confirms device type and timing without requiring any further interaction.
The last of these is useful for reconnaissance: knowing that an executive scanned a particular code
at a particular time and on a particular device is information that feeds subsequent attacks.

## Planted documents

Documents left in printers, photocopiers, and shared trays get read. This is a normal office
behaviour, because documents left in shared spaces are assumed to be intended for communal awareness.
A document that appears to contain sensitive internal information creates an obligation in most people
to find out what it is and whether they should do something about it.

A planted document can contain QR codes, shortened URLs, or phone numbers that lead to attacker-controlled
resources. A convincing internal memo about a security incident, a fake policy change that requires
employees to re-authenticate their accounts, or a notice about a new supplier portal all create
plausible reasons to interact with a link.

The document does not need to be elaborate. A single page on familiar-looking letterhead, left where
it will be found by the right person, can achieve more than a technically sophisticated attack.

## Runbooks

- [Playbook: Physical access engagement](../playbooks/physical-entry.md) — USB drop placement and QR sticker deployment covered in the on-site phase
- [Runbook: Quishing campaign](../runbooks/quishing-campaign.md) — physical QR sticker variant


