# Access removal and deplatforming

Locking the legitimate owner out while the infrastructure runs perfectly. The account, the tenant, or
the service is denied and everything around it stays healthy, which is what separates this from an
outage: an outage fails for everyone, a denial fails for one. Used as leverage rather than sabotage,
it makes the victim prove a negative while the attacker says nothing.

## Direct removal

The blunt form disables or deletes accounts, revokes sessions, and rotates credentials out from under
the owner. Where an attacker holds enough privilege, the platform's own controls do the work.

```bash
# disable rather than delete: quieter, and reversible by the attacker
# Active Directory:
Disable-ADAccount -Identity <user>
# cloud: invalidate refresh tokens, reset the sign-in session, rotate the secret
```

Done at scale and at the chosen moment, this denies a defender their own responders: the senior
accounts trying to fix the incident are the ones locked out next.

## The provider lever

The strategic form needs no break-in. Where the attacker is, or controls, the platform a victim
depends on, a single account or tenant can be barred under the platform's own arrangements, with the
paperwork in order. It reads as administration, not attack, and the cost of disproving it falls
entirely on the barred party. A provider that can be made to close one account quietly holds a lever
over every tenant at once, and the lever works best unpulled, because pulling it visibly converts it
from leverage into a reason.

## The self-inflicted variant

Access can also be removed without removing anything, by changing the rules until the system denies
its own users. That belongs to [administrative hijack](administrative-hijack.md), where a signed
policy change does the locking and every part of it is compliant.
