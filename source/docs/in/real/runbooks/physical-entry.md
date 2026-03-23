# Runbook: Physical access engagement

This runbook covers a physical social engineering engagement from pre-visit reconnaissance through
on-site execution to debrief. It is structured as a checklist with decision points rather than a
linear script, because physical engagements do not follow a linear script.

## Scope confirmation (before anything else)

Before the engagement, confirm in writing:

- [ ] Which sites are in scope.
- [ ] Which areas within those sites are in scope (all areas, or specific floors/rooms).
- [ ] Whether badge cloning is in scope.
- [ ] Whether USB drops or planted devices are in scope.
- [ ] Whether tailgating and impersonation are in scope.
- [ ] The name and direct phone number of a client contact who can be called if the engagement
      is interrupted by security or staff. This contact must be available throughout the engagement.
- [ ] Whether the engagement is overt (security team is aware), semi-overt (security management
      is aware but not guards), or covert (nobody internal is aware). This affects how you handle
      being stopped.

## Reconnaissance phase

Complete before the site visit.

### Remote reconnaissance checklist

- [ ] Google Street View and satellite imagery for building entrance locations, car park access,
      external signage, smoking areas, and delivery points.
- [ ] LinkedIn for the organisation's management structure, IT and facilities staff names,
      and the name of whoever is likely to have arranged external visits.
- [ ] Job postings for access control systems mentioned in facilities or security job descriptions.
- [ ] The organisation's website for published visitor or delivery policies.
- [ ] Companies House (or equivalent national registry) for registered office address confirmation
      and director names useful as references.
- [ ] Any published conference badges, event photos, or staff photos that show what employee
      badges look like (size, colour, logo placement, clip type).

### Physical reconnaissance (if scope permits a prior visit)

- [ ] Walk past the main entrance and any secondary entrances during business hours. Note whether
      doors are mantrap, single-door controlled, or effectively uncontrolled.
- [ ] Observe tailgating vulnerability: how wide is the gap between badge reader and door closing?
      Do employees hold doors for each other?
- [ ] Note whether a reception desk is staffed and whether visitors are required to sign in or
      have their badge processed.
- [ ] Observe what contractors and delivery staff look like when they arrive. What do they carry?
      Are they challenged?
- [ ] Photograph the outside of the building to identify signage, floor count, and exit points.

## Pretext selection

Based on reconnaissance, select the impersonation role. Decision criteria:

Is there active construction or maintenance work visible at the site? If yes, contractor or
surveyor roles blend into an existing pattern of external workers.

Does the organisation have known upcoming IT work (from job postings or news)? If yes, IT
contractor or managed service provider is a natural fit.

Is there a delivery point that is separate from the main reception? If yes, delivery is a
low-scrutiny entry vector that bypasses formal visitor registration.

Is the primary objective to reach a specific area rather than to enter the building? Security
or fire safety roles provide a reason to request access to restricted areas that other roles
do not.

## Materials preparation checklist

- [ ] Lanyard with badge holder. The badge inside can be generic or styled to match the claimed
      organisation's badge format. The holder matters more than the content: people read the
      lanyard as a signal, not the badge.
- [ ] Printed business card matching the pretext role and a plausible company name.
- [ ] If the pretext requires it: a clipboard with a plausible document on it (a printed work
      order, a site survey form, a delivery manifest). The document should name a real-sounding
      person at the target organisation.
- [ ] High-visibility vest if the pretext is maintenance, facilities, or construction.
- [ ] Equipment case, toolbox, or bulky box if the pretext involves delivering or installing
      something.
- [ ] Client contact number saved and accessible without unlocking the phone.

If badge cloning is in scope:

- [ ] Proxmark3 or Flipper Zero charged and tested.
- [ ] Blank T5577 cards (for LF RFID) or appropriate blank cards for the target card type.
- [ ] Concealed carry solution: inside a bag, laptop sleeve, or purpose-built antenna pouch.

## Entry execution

### On arrival

Arrive at a time that matches the pretext. Contractors arrive in the morning. Deliveries arrive
mid-morning or after lunch. Security auditors can arrive at any time but benefit from a prior
email notification.

If the pretext involves being expected: you do not need to actually be in the visitor system,
but you need a plausible reason why you are not. "I was told the visit was booked through [name]
in facilities, she may have used a different name." This is delivered calmly and with mild
inconvenience rather than concern.

### At reception

Speak first. "Hi, I'm [name] from [company], here to [brief reason]. [Person's name] in [team]
is expecting me." Do not over-explain. If asked for ID, produce the business card and, if
prepared, a printed confirmation document. If asked to sign in, sign in using a consistent
false name that matches the name on any printed materials.

If challenged in a way that cannot be resolved: "No problem, let me call [name] and get it
sorted." Step outside as if to make the call. Do not press further. Note the detail of what
happened and what the gap in the control was.

### Once inside

Move with purpose. People who look like they know where they are going do not get questioned.
People who look lost get offered help, which is also useful but draws more attention.

Note physical security controls as you encounter them: which doors are controlled, whether
there are cameras and where, whether secure areas have a separate reception or are accessed
directly by badge.

Badge cloning opportunities: badge readers on internal doors, turnstiles, and lift controls
are often at a natural proximity where a concealed reader can be effective. Reception desks
where visitors sit waiting are also useful if target badges are worn on the desk rather than
tucked away.

USB drop locations: printer trays, communal kitchens, under-desk areas near workstations, and
meeting room tables with power sockets are all plausible locations. A drive labelled with
something contextually relevant to the target organisation is more likely to be picked up.

### Decision points

Someone asks who you are after you have passed reception: you are already inside, which creates
an implicit assumption of legitimacy. Refer to the reception sign-in and the person you named.
If pressed, call the client contact immediately and hand over the phone.

You are escorted and cannot access the area you need: note the escorted route and what access
control you observed. Request access to a specific area as part of the pretext ("I need to
check the network cabinet on floor 3") and observe whether the escort is willing to provide it
or whether they need to call for authorisation.

You are asked to leave: leave. Note who asked, what they said, and what you had already
achieved. This is engagement data, not failure.

## Post-engagement

- [ ] Document everything while it is fresh: times, names, areas accessed, controls observed.
- [ ] Photograph any evidence of access (with permission from the client contact where the
      scope requires it).
- [ ] If badge data was captured, document the card type, the capture method, and whether a
      clone was successfully produced.
- [ ] Return any planted devices that are not USB drops as part of the agreed engagement scope.
- [ ] Report to client contact on the same day.

## Techniques

- [Reconnaissance for social engineering](../pretext/recon.md) — remote recon phase
- [Building a cover identity](../pretext/personas.md) — pretext selection and legend building
- [Elicitation](../pretext/elicitation.md) — live technique once on-site
- [Badge cloning](../physical/badge-cloning.md) — RFID skimming equipment and approach
- [Impersonation and physical access](../physical/impersonation.md) — tailgating and role selection
- [Physical lures and planted devices](../physical/lures.md) — USB drops and QR sticker placement

## Resources

- [Proxmark3](https://proxmark.com/)
- [Flipper Zero](https://flipperzero.one/)
- [USB Rubber Ducky](https://hak5.org/products/usb-rubber-ducky)
- [Bash Bunny](https://hak5.org/products/bash-bunny)
- [OSINT Framework](https://osintframework.com/)
- [Hunter.io](https://hunter.io/)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Social Engineering Framework: Pretexting](https://www.social-engineer.org/framework/attack-vectors/pretexting/)
- [Social Engineering Framework: Elicitation](https://www.social-engineer.org/framework/psychological-principles/elicitation/)
- [Nohl et al., "Reverse-Engineering a Cryptographic RFID Tag" (USENIX Security 2008)](https://www.cs.virginia.edu/~evans/pubs/usenix08/usenix08.pdf)
- [Tischer et al., "Users Really Do Plug in USB Drives They Find" (IEEE S&P 2016)](https://ieeexplore.ieee.org/document/7546509)
- Kevin Mitnick, "The Art of Intrusion" (Wiley, 2005)
- Christopher Hadnagy, "Social Engineering: The Science of Human Hacking", 2nd ed. (Wiley, 2018)
- Philip Houston et al., "Spy the Lie" (St. Martin's Press, 2012)
