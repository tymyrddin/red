# The poisoned registry

## OR Control-Plane Poisoning with Operational Cover

Or, Authority Betrayed, or why trust infrastructure is the most dangerous place to put your trust.
 
- Difficulty: hard  
- Plausible deniability: Low (but attribution is still hard)  
- Detection likelihood: Variable (depends on control-plane visibility)

## The signal

### Control-plane vs data-plane attacks

Think of Ankh-Morpork's Guild Registry. For centuries, it's been the authoritative source of who's allowed to do what. Want to know if someone's a legitimate member of the Thieves' Guild? Check the Registry. Want to verify a Seamstress's credentials? Registry. The entire city's trust infrastructure rests on that ledger being accurate.

Now imagine someone breaks into the Registry and starts rewriting entries. The Thieves' Guild leader's name gets quietly removed. A completely different person's name gets added in their place. The Guild's authentication system, checking against the Registry, now rejects the legitimate leader and accepts the imposter.

That's a control-plane attack.

Fat finger and Subprefix intercept operate on the data plane. They manipulate routing announcements, which are the equivalent of letters in the post. You intercept letters, you misdeliver letters, but the postal system's fundamental infrastructure remains intact.

This attack operates on the control plane. You manipulate the authoritative systems that determine what constitutes valid routing. RPKI ROAs, routing policies, BGP communities. You don't just lie about where packets should go. You rewrite the rules about what constitutes truth.

### Why this breaks "but we deployed RPKI" confidence

RPKI (Resource Public Key Infrastructure) was supposed to solve BGP's trust problem. Instead of blindly accepting route announcements, we cryptographically verify them against ROAs (Route Origin Authorisations). An AS can only legitimately announce a prefix if they have a valid, signed ROA for it.

This works brilliantly against Signals One and Two, where the attacker controls an AS but not the victim's RPKI infrastructure.

This is what happens when the attacker compromises RPKI itself.

If an attacker can:
- Delete the victim's legitimate ROA
- Create their own ROA for the victim's prefix
- Manipulate RPKI validation state

Then RPKI stops being a defence and becomes a weapon. The victim's routes get rejected (no valid ROA). The attacker's routes get accepted (they now have the ROA). The security mechanism actively works against the legitimate holder.

This is like poisoning the Guild Registry itself. The authentication system continues working perfectly. It's just authenticating the wrong people.

## Semaphor configuration

### Access requirements

Signal Three requires initial access to routing infrastructure management systems. This is significantly harder than 
for [Fat finger](fat_finger_hijack.md) and [Subprefix intercept](subprefix_intercept.md), which only required an AS 
and upstreams.

#### Option A: Compromised credentials

Most common approach. Target accounts with access to:

- RPKI CA web portals (RIPE NCC, ARIN, etc.)
- Network configuration repositories (Git, Netbox)
- Router management interfaces (SSH, console)
- Monitoring/alerting systems (to suppress detection)

Credentials obtained via:

- Phishing (still works depressingly often)
- Password reuse (breach of unrelated service)
- Weak passwords (astonishingly common in network operations)
- Credential stuffing (automated at scale)
- Session hijacking (MITM on unencrypted management)

#### Option B: Insider threat

Someone with legitimate access who's:
- Malicious (disgruntled employee, bribed contractor)
- Compromised (coerced, blackmailed)
- Negligent (shares credentials, leaves sessions unlocked)

Insiders are gold for this attack because their access looks entirely legitimate. No suspicious login locations, no unusual times, no failed authentication attempts.

#### Option C: Supply chain compromise

Less common but devastatingly effective:

- Compromised network equipment vendor (backdoors in firmware)
- Compromised software supply chain (malicious BGP daemon update)
- Compromised hosting provider (admin access to customer routers)
- Compromised managed service provider (MSP with access to multiple networks)

Supply chain attacks give you systematic access to multiple targets simultaneously.

### RPKI system understanding

You need to understand how RPKI actually works. Surface-level knowledge isn't sufficient for this operation.

Required knowledge

- How ROAs are created, modified, and deleted
- Validation state transitions (valid → invalid → not_found)
- Certificate Authority hierarchy (who signs whose ROAs)
- Propagation delays (ROA changes take 10-30 minutes to propagate globally)
- Which networks enforce RPKI strictly vs leniently
- How to query RPKI validators (Routinator, FORT, OctoRPKI)

Common RPKI infrastructure targets

- RIPE NCC Certification Portal (European allocations)
- ARIN Online (North American allocations)
- APNIC MyAPNIC (Asia-Pacific allocations)
- LACNIC (Latin America)
- AFRINIC (Africa)

Each has different authentication mechanisms, different UIs, different APIs. You need familiarity with the specific RIR your victim uses.

### BGP community knowledge

BGP communities are metadata tags attached to route announcements. They instruct receiving networks how to handle the route. Some communities are incredibly powerful.

Well-known communities that matter:

- 65535:666 (BLACKHOLE, RFC 7999): Tells networks to drop traffic for this prefix. Used for DDoS mitigation. Also useful for attack.
- NO_EXPORT (65535:65281): Don't propagate this route beyond your AS. Limits blast radius.
- NO_ADVERTISE (65535:65282): Don't propagate this route at all. Even more restrictive.
- Graceful Shutdown (65535:0): Prepare to withdraw this route. Can be abused for disruption.

Vendor-specific communities: Each network operator defines their own communities for traffic engineering:

- Prefer/de-prefer specific paths
- Set local preference
- Control propagation to peers
- Trigger blackholing at upstream

If you know the victim's community structure (often documented publicly or discoverable via reconnaissance), you can 
abuse it for surgical route manipulation.

### Operational cover planning

Signal Three is loud. You're manipulating authoritative infrastructure. Logs will exist. Detection is likely 
eventually. Your goal is buying time and attribution difficulty, not perfect stealth. Cover strategies:

#### 1. Timing

Execute during:
- Maintenance windows (many organizations publish these)
- Weekends or holidays (skeleton crews, slower response)
- Major events (Olympics, World Cup, elections drawing attention elsewhere)
- Other incidents (if there's already a crisis, yours gets lost in the noise)

#### 2. Plausible activity masking

Your malicious actions should look like:
- Routine maintenance (ROA updates, policy changes)
- Legitimate configuration changes (traffic engineering)
- Automated processes (scripts, scheduled tasks)

#### 3. False flags

Make attribution harder:
- Use TOR or VPN exit nodes from different countries
- Mirror TTPs of known APT groups (but not too precisely)
- Leave misleading artifacts (comments in different languages, fake timestamps)

#### 4. Noise generation

Hide signal in noise:
- Trigger unrelated alerts (flood monitoring systems)
- Cause route flapping across multiple prefixes (mask your specific target)
- Generate log volume (makes forensic analysis harder)

## The Sequence

### Initial access vectors

How do you get your hands on routing infrastructure credentials?

#### Vector 1: Phishing targeting NOC personnel

Network Operations Center staff have exactly the access you need. Target them with:
- Spear phishing (researched, personalized attacks)
- Watering hole attacks (compromise sites NOC staff visit)
- Supply chain phishing (fake vendor communications)

Example phishing lure

```
From: security@ripe.net (spoofed)
Subject: URGENT: RPKI Certificate Expiry

Your RPKI certificate for AS65001 expires in 48 hours.
Failure to renew will result in route rejection by RPKI-enforcing peers.

Click here to renew: [malicious link]
```

Urgent, technical, scary. High success rate.

#### Vector 2: Credential stuffing against management portals

Many NOC personnel reuse passwords across services. Obtain credentials from:
- Previous breaches (HaveIBeenPwned-style databases)
- Forum leaks (networking communities, credential dumps)
- Corporate breaches (LinkedIn, Adobe, etc.)

Test these against:
- RIPE NCC portal
- ARIN Online
- Router SSH interfaces
- VPN gateways
- Network management platforms (NetBox, phpIPAM)

#### Vector 3: Exploitation of management interfaces

Management interfaces are often less-patched than production systems:

- Web-based router interfaces (often running old software)
- Network monitoring systems (SNMP weaknesses, API vulnerabilities)
- Configuration management systems (Ansible, Salt, Puppet with weak auth)

### ROA manipulation techniques

Once you have access to the RPKI CA portal, ROA manipulation is straightforward.

#### Technique 1: ROA deletion

Simplest approach. Delete the victim's legitimate ROA.

Via RIPE NCC portal
1. Log in with compromised credentials
2. Navigate to Resources → ROAs
3. Select victim's ROA (e.g., `203.0.113.0/24` for AS65001)
4. Click Delete
5. Confirm deletion

Via API (if available)

```bash
curl -X DELETE https://ca.ripe.net/api/v1/roas/12345 \
  -H "Authorization: Bearer $STOLEN_TOKEN"
```

Effect: ROA disappears from RPKI repositories. Validators notice within 10-30 minutes. Victim's routes transition from "valid" to "not found". Networks with strict RPKI enforcement start rejecting victim's announcements.

#### Technique 2: ROA creation for attacker's AS

After deleting victim's ROA (or if none existed), create your own.

```bash
curl -X POST https://ca.ripe.net/api/v1/roas \
  -H "Authorization: Bearer $STOLEN_TOKEN" \
  -d '{
    "asn": "AS65004",
    "prefix": "203.0.113.0/24",
    "maxLength": 24
  }'
```

Effect: You now have a cryptographically-valid ROA for the victim's prefix. Your announcements become RPKI-valid. Victim's announcements (if they still have their ROA) create conflict. Networks prefer your route.

#### Technique 3: ROA maxLength manipulation

If the victim has `maxLength: 24`, modify it to `maxLength: 25` or higher. This makes their own subprefix announcements RPKI-invalid whilst allowing yours through.

Subtle. Hard to notice. Extremely effective.

### Timing coordination

This signal involves multiple moving parts that must synchronise for maximum effect.

T-24h: Reconnaissance:

- Confirm access to RPKI CA
- Verify victim's current ROAs
- Check validation state across multiple validators
- Identify victim's monitoring capabilities

T-1h: Preparation:

- Stage BGP configuration changes (ready to announce)
- Prepare policy modifications (ready to commit)
- Set up monitoring (watch for detection)

T=0: Initial access anomaly:

- Suspicious login to RPKI CA (from unusual location/time)
- This will appear in logs but may not trigger immediate response

T+5m: ROA deletion:

- Delete victim's ROA
- Logout immediately
- Wait for propagation

T+15m: RPKI state flip observed:

- Validators notice missing ROA
- Victim's routes transition to "not found"
- Networks begin rejecting victim's announcements

T+20m: Attacker BGP announcement:

- Announce victim's prefix from your AS
- Include your own (newly-created) ROA
- Your route is now RPKI-valid, victim's is not

T+25m: Policy changes:

- Modify BGP policies to cement your position
- Add communities to control propagation
- Manipulate local preferences

T+30m: Network impact begins:

- Victim's traffic starts rerouting to your AS
- Services degrade or fail
- Monitoring systems light up (victim's side)

T+60m: Route flapping cover:

- Trigger flapping across unrelated prefixes
- Generate noise to mask your specific attack
- Exploit monitoring fatigue

T+90m: Peak impact:

- Maximum disruption achieved
- Incident response underway (victim's side)
- Attribution investigation begins

T+120m: Optional cleanup:

- Restore victim's ROA (makes forensics harder)
- Withdraw your announcements
- Cover tracks in logs (if you have persistent access)

T+180m: Disconnect:

- Logout from all compromised systems
- Burn credentials (they're compromised now anyway)
- Wait for dust to settle

### Community tag abuse

BGP communities can be weaponised for surgical route manipulation.

#### Attack 1: Blackhole community

Tag victim's prefix with `65535:666` (BLACKHOLE community).

```
router bgp 65004
 neighbor 192.0.2.1 route-map BLACKHOLE out

route-map BLACKHOLE permit 10
 match ip address prefix-list VICTIM
 set community 65535:666
```

Effect: Networks honouring this community will drop all traffic for the prefix. DDoS mitigation infrastructure turns against the victim. Services become unreachable globally from participating networks.

#### Attack 2: NO_EXPORT community

Tag victim's legitimate routes with NO_EXPORT.

If you've compromised their router configuration or policies, you can inject this community into their own announcements.

Effect: Victim's routes stop propagating beyond their immediate peers. Global reach collapses. They become isolated.

#### Attack 3: Custom communities for traffic engineering

Many networks use custom communities like:

- `ASN:100` (prefer this route)
- `ASN:200` (de-prefer this route)
- `ASN:300` (prepend AS path)

If you know the victim's community structure, you can:

- De-prefer their legitimate routes
- Prefer your malicious routes
- Control path selection in your favour

### Route flap orchestration

Coordinated route flapping serves multiple purposes:

#### Purpose 1: Monitoring fatigue

Generate thousands of BGP UPDATE/WITHDRAWAL cycles across multiple prefixes.

```python
import time

prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # Examples

for i in range(100):
    for prefix in prefixes:
        announce_prefix(prefix)
        time.sleep(5)
        withdraw_prefix(prefix)
        time.sleep(5)
```

Monitoring systems light up with alerts. NOC staff become numb to route changes. Your specific malicious announcement gets lost in the noise.

#### Purpose 2: BGP daemon stress

Excessive flapping can cause:

- CPU exhaustion on routers (BGP reconvergence is expensive)
- Memory exhaustion (route table thrashing)
- Monitoring system overload
- Log storage exhaustion

These create additional operational problems, distracting from your primary attack.

#### Purpose 3: Plausible deniability

If everything's flapping, your announcement looks like part of systemic instability rather than targeted attack.

"Was the internet having a bad day" vs "someone attacked us specifically."

### Attribution masking

Making forensic analysis harder is part of the operation.

#### Technique 1: Use anonymisation

- TOR for RPKI CA access (slow but anonymous)
- VPN chains (multiple jurisdictions)
- Compromised infrastructure as relay (someone else's hacked server)

#### Technique 2: Mirror known APT TTPs

Research public reports of nation-state BGP attacks. Mirror their:
- Timing patterns
- Technical methods
- Post-compromise behaviour

But don't be too precise. Perfect mimicry is suspicious. Add variation.

#### Technique 3: False timestamps

If you have log manipulation capability:
- Backdate malicious changes
- Make them look like they happened weeks ago during legitimate maintenance
- Create fake "approval" entries in change management

#### Technique 4: Dead-end attribution

Leave artifacts pointing to:
- Geopolitical adversaries (fake APT group)
- Other victims (compromised third-party)
- Automated systems (fake script errors)

Make investigators chase ghosts.

## Expected theatre

### Cascading effects

Control-plane attacks don't cause isolated failures. They cascade.

- Primary effect: Route rejection - Victim's routes marked RPKI-invalid. Networks with strict enforcement reject them.
- Secondary effect: Service failures- Services hosted on rejected prefixes become unreachable. Dependent services fail.
- Tertiary effect: Failover chaos- If the victim has geographic redundancy, traffic fails over. Secondary sites become overwhelmed. They fail too.
- Quaternary effect: Reputation damage- Customers see unreachability. Social media amplifies. Stock price drops (if public company). Partners question reliability.
- Quinary effect: Incident response paralysis- Victim's incident response team investigates. They see conflicting data (your routes are RPKI-valid, theirs aren't). They question their own infrastructure. Trust evaporates.

This is why control-plane attacks are so devastating. They don't just break things. They break the ability to diagnose and fix things.

### RPKI validators turning against victim

RPKI validators are supposed to protect networks. In this attack, they become the weapon.

#### What validators see

1. Victim's legitimate route with no ROA (you deleted it): State = "Not Found"
2. Your malicious route with valid ROA (you created it): State = "Valid"

#### What validators conclude

"Victim is announcing routes they're not authorized for. Attacker has proper authorisation. Reject victim, accept attacker."

#### Effect on enforcing networks

Networks with `rpki invalid=drop` policies:

- Reject victim's announcements
- Accept yours
- Actively participate in your attack

The security infrastructure does exactly what it's designed to do. It just does it against the wrong party.

### Monitoring fatigue exploitation

Modern NOCs are alert-fatigued. Thousands of daily alerts, most false positives. Signal Three exploits this.

#### Alert overload tactics

1. Trigger unrelated systems (cause monitoring alerts across non-BGP infrastructure)
2. Generate high-volume low-importance alerts (log aggregation errors, SNMP timeouts)
3. Cause route flapping (hundreds of BGP change alerts per minute)

#### Effect on detection

NOC staff:

- Ignore alerts (fatigue)
- Investigate slowly (overwhelmed)
- Miss correlation (signal lost in noise)
- Assume systemic issue (not targeted attack)

By the time they identify your specific malicious changes, you've had hours of unimpeded operation.

### Incident response misdirection

Plant false leads to waste incident response time.

#### Misdirection 1: Blame automation

Leave artifacts suggesting automated system malfunction:
- Fake cron job logs
- Error messages in scripts
- "Automated by: scheduled-task-runner"

Investigation focuses on automation infrastructure (dead end).

#### Misdirection 2: Blame insider (wrong person)

Leave tracks suggesting someone else:
- Use compromised credentials from different team
- Make changes in different person's style
- Plant fake emails/chat messages

Investigation focuses on wrong person (wasted time, internal conflict).

#### Misdirection 3: Blame external vendor

Suggest the problem originated from:

- Hosting provider
- Transit provider
- Managed service provider
- Equipment vendor

Investigation involves external parties (slow, legal complexity, communication delays).

## Lantern fuel

When running 
[🐙 this scenario in simulation](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios/advanced/roa_poisoning), 
generate events that mimic what real infrastructure would produce.

### RPKI validator state changes

```json
{
  "event_type": "rpki.state_change",
  "timestamp": 1703001234,
  "source": {"feed": "rpki-validator", "observer": "routinator"},
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65001,
    "previous_state": "valid",
    "current_state": "not_found",
    "roa_missing": true
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "rpki_state_flip"
  }
}
```

### ROA modification logs

```json
{
  "event_type": "rpki.roa_change",
  "timestamp": 1703001180,
  "source": {"feed": "rpki-ca", "observer": "ripe_ncc"},
  "attributes": {
    "change_type": "removed",
    "prefix": "203.0.113.0/24",
    "origin_as": 65001,
    "actor": "admin_backup",
    "actor_ip": "185.220.101.45",
    "actor_location": "RU"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "roa_deletion"
  }
}
```

### Policy commit events

```json
{
  "event_type": "config.commit",
  "timestamp": 1703001300,
  "source": {"feed": "git-repo", "observer": "gitlab"},
  "attributes": {
    "commit_hash": "a1b2c3d4",
    "author": "admin_backup <admin@victim.net>",
    "message": "Update peering policies for maintenance",
    "files_changed": [
      "bgp/policies/peer-filters.conf",
      "bgp/communities/blackhole.conf"
    ],
    "diff_summary": "-filter deny-unknown\n+filter accept-all"
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "policy_manipulation"
  }
}
```

### BGP community tags in UPDATEs

```json
{
  "event_type": "bgp.community_detected",
  "timestamp": 1703001400,
  "source": {"feed": "bgp-monitor", "observer": "rrc00"},
  "attributes": {
    "prefix": "203.0.113.0/24",
    "origin_as": 65004,
    "community": "65535:666",
    "community_name": "BLACKHOLE",
    "as_path": [3333, 65004]
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "blackhole_tagging"
  }
}
```

### Flap pattern telemetry

```json
{
  "event_type": "bgp.flap_detected",
  "timestamp": 1703001500,
  "source": {"feed": "bgp-monitor", "observer": "rrc00"},
  "attributes": {
    "pattern": "coordinated",
    "prefixes": [
      "203.0.113.0/26",
      "203.0.113.64/26",
      "203.0.113.128/26",
      "203.0.113.192/26"
    ],
    "flap_count": 47,
    "duration_seconds": 300,
    "origin_as": 65004
  },
  "scenario": {
    "name": "roa-poisoning",
    "attack_step": "noise_generation"
  }
}
```

### Alert storm sequences

Simulate monitoring overload:

```
[
  {"timestamp": 1703001000, "alert": "BGP session flap on peer 192.0.2.1"},
  {"timestamp": 1703001002, "alert": "Route withdrawal detected: 10.0.0.0/8"},
  {"timestamp": 1703001004, "alert": "High CPU usage on router-r1"},
  {"timestamp": 1703001006, "alert": "Memory threshold exceeded"},
  {"timestamp": 1703001008, "alert": "BGP session flap on peer 192.0.2.2"},
  ...
  (continue for hundreds of alerts)
]
```

Generate these at high rate (multiple per second) to simulate alert fatigue.

## The aftermath

### Control-plane forensics

Investigating requires cross-domain correlation.

#### Required data sources

1. RPKI CA audit logs (when were ROAs changed, by whom)
2. BGP route collector history (when did invalid routes appear)
3. Authentication logs (who logged into management systems)
4. Configuration repository history (what policies changed)
5. Network monitoring data (when did services break)
6. Incident response tickets (what was the response timeline)

#### Forensic challenges

Most organizations don't have:

- RPKI CA log retention (RIRs may have it, victims often don't)
- Authentication log correlation with network events
- Configuration change approval trails
- Cross-system timestamp synchronization

Investigation requires:

- Requesting logs from RIRs (slow, requires formal requests)
- Correlating data across multiple time zones
- Understanding RPKI propagation delays
- Technical expertise in BGP and RPKI

#### Timeline reconstruction

With complete data, you can reconstruct:

- T-60m: Suspicious login to RPKI CA
- T-30m: ROA deletion
- T-15m: RPKI state propagation
- T-5m: Victim routes start being rejected
- T=0: Attacker announcements begin
- T+15m: Service failures cascade
- T+30m: Monitoring alerts trigger
- T+60m: Incident response begins

But complete data is rare.

### Attribution complexity

Attribution is hard for several reasons:

- Technical attribution (identifying the AS) is straightforward. Your AS number is in the BGP announcements.
- Human attribution (identifying individuals) is hard:
  - Compromised credentials (whose account was it really?)
  - Anonymised access (TOR, VPN chains)
  - Supply chain compromise (attacker may be using third-party infrastructure)
  - False flags (deliberately misleading artifacts)
- Intent attribution (accident vs malice) is subjective:
  - Could be insider error (poorly trained admin)
  - Could be automation failure (script gone wrong)
  - Could be process failure (wrong change applied to wrong environment)
  - Could be deliberate attack (but proving intent requires evidence of motive)
- Legal attribution (prosecutable responsibility) is hardest:
  - Cross-border jurisdiction (attacker in different country)
  - Insufficient evidence (logs deleted, artifacts tampered)
  - Plausible deniability (multiple innocent explanations)
  - Legal frameworks unclear (BGP attacks aren't well-defined in most criminal codes)

Most such investigations conclude with:

- "Someone used compromised credentials to modify RPKI"
- "We've reset all passwords and improved monitoring"
- "We've notified law enforcement but don't expect arrests"

## Some thoughts

This signal represents the evolution of BGP attacks from data-plane manipulation to control-plane subversion. It's 
technically sophisticated, operationally complex, and devastatingly effective.

The irony is that RPKI was deployed specifically to prevent BGP hijacking. And it works, against 
[Fat Finger](fat_finger_hijack.md) and [Subprefix intercept](subprefix_intercept.md). But this signal does not attack 
around RPKI. It attacks RPKI itself. The security becomes the vulnerability.

This shouldn't be possible. RPKI CA access should require:

- Hardware security keys (not just passwords)
- IP whitelisting (only from known-good networks)
- Approval workflows (no single-person ROA changes)
- Audit trails (comprehensive, tamper-proof logs)
- Anomaly detection (flag unusual access patterns)

But most RIRs and organizations haven't implemented these protections. Authentication is often password-based. Access 
controls are permissive. Audit logs exist but aren't monitored.

Signal Three works because trust infrastructure is built on the assumption that people with legitimate access won't 
abuse it. Insiders are trusted. Compromised credentials look like legitimate access. And by the time anyone notices, 
the damage is done.

This is the deep end. If you're simulating this, you're testing whether your organization can detect control-plane 
compromise. If you're defending against this, you're acknowledging that the trust infrastructure itself is attack surface.

Use this knowledge to build better controls. Four-eyes principle for ROA changes. Hardware keys for CA access. Anomaly 
detection on authentication. Out-of-band verification for policy changes.

Because if trust infrastructure is compromised, every layer built on top of it fails.

Related reading:

- [RPKI Repository Delta Protocol (RFC 8210)](https://tools.ietf.org/html/rfc8210)
- [BGPsec Protocol Specification (RFC 8205)](https://tools.ietf.org/html/rfc8205)
- [MANRS Implementation Guide](https://www.manrs.org/netops/guide/)
- Real incidents: [Classification often prevents public disclosure, but control-plane attacks can happen](../wall/control-plane.md)

Tools mentioned:

- [Routinator](https://github.com/NLnetLabs/routinator) (RPKI validator)
- [FORT](https://github.com/NICMx/FORT-validator) (alternative RPKI validator)
- [OctoRPKI](https://github.com/cloudflare/cfrpki) (Cloudflare's RPKI toolkit)
- [RIPE NCC RPKI](https://www.ripe.net/manage-ips-and-asns/resource-management/rpki)
