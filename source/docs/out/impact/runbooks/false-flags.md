# False flags and attribution misdirection

Planting artefacts that suggest a different threat actor is responsible
for the operation. Used in red team exercises to test whether the
organisation's incident response process attributes correctly, or whether
investigators can be led down the wrong path.

## Why attribution matters

If an organisation misattributes an attack, they may:
- Apply mitigations appropriate to the wrong threat actor
- Spend investigation time chasing irrelevant indicators
- Make incorrect decisions about disclosure and regulatory notification
- Fail to remediate the actual entry point because they focused on the
  wrong one

Testing attribution resistance is a legitimate component of red team exercises.

## Linguistic and cultural artefacts

Language artefacts in malware and tooling suggest the developer's native
language and culture:

```python
# add comments in a target language (generated with a translation tool)
# Mandarin Chinese: commonly associated with certain APT groups
# 系统监控服务 = "system monitoring service"

# embed a fake developer string in a binary
fake_sig = b'\xe7\xb3\xbb\xe7\xbb\x9f\xe7\x9b\x91\xe6\x8e\xa7\xe6\x9c\x8d\xe5\x8a\xa1'
```

```powershell
# change system locale to a target nation's locale (temporary)
Set-WinSystemLocale -SystemLocale zh-CN  # Simplified Chinese
Set-WinUILanguageOverride -Language zh-CN
# revert after planting the artefact
Set-WinSystemLocale -SystemLocale en-GB
```

## Infrastructure misdirection

Using infrastructure associated with, or hosted in, regions associated with
a target threat actor:

- Rent VPS in a country commonly associated with the target APT group
- Use VPN exit nodes in that country for operational traffic
- Register domains using naming patterns similar to known threat actor
  infrastructure

```bash
# check what country an IP is associated with (for infrastructure selection)
curl -s https://ipapi.co/IP_ADDRESS/json/ | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['country_name'], d['org'])"
```

## Code and tooling reuse

Using code or tools publicly associated with a known threat actor:

```bash
# clone a publicly available APT tool from a public threat intelligence report
# modify identifiers slightly to avoid exact hash matching
# deploy in a way that leaves the signature in memory or on disk

# example: use a known APT's C2 framework signature
# (specific tools not listed; refer to public threat intelligence reports)
```

```powershell
# embed a fake PDB path in a compiled binary
# PDB paths often reveal development environment details
# a fake path suggesting a foreign development environment
$fake_pdb = 'C:\Users\admin\Documents\Projects\SysMon\Release\sysmon.pdb'
# (PDB path injection requires post-compilation modification of the PE header)
```

## Behavioural misdirection

Operating in ways that resemble a known threat actor's tactics:

```bash
# use specific known tools associated with a target APT group
# mimic their known timing patterns (e.g., operating only during business hours
# in the target APT's timezone)

# example: APT timing; if mimicking a group known to work 09:00-18:00 UTC+8:
# schedule all operations between 01:00-10:00 UTC
```

## Fake insider threat indicators

Planting evidence suggesting the attack was an insider:

```powershell
# access a file from a legitimate user's account context (using stolen credentials)
# the access log shows the legitimate user's username

# create a fake account that resembles a disgruntled employee
New-ADUser -Name 'temp.contractor' -UserPrincipalName 'temp.contractor@domain.local' `
  -Description 'Temporary contractor account (expires 2024-12-31)'

# access sensitive data from this account, then disable it
Disable-ADAccount -Identity 'temp.contractor'
```

## Counter-attribution testing checklist

A false flag exercise should test whether investigators:

- Anchor on the first plausible attribution and stop investigating
- Verify attribution against multiple independent indicators
- Check whether planted artefacts are consistent with each other
- Investigate whether the attributed actor has a motive for this target
- Identify the actual entry point independently of the attributed actor

The outcome measure is not whether investigators are deceived, but how
they handle uncertainty and whether they have processes for challenging
initial attributions.

## Operational notes

- False flags should be planted early: artefacts from the initial access
  stage are more credible than those added during cleanup
- Inconsistent false flags are worse than none: if the linguistic artefacts
  suggest one country and the infrastructure suggests another, analysts
  will identify both as planted
- The most effective false flags are minimal: one or two consistent indicators
  that fit the attributed actor's known TTPs, not a comprehensive set of
  every known indicator
- In a real engagement (not a red team exercise), attribution misdirection
  may constitute a criminal offence in some jurisdictions if it causes law
  enforcement to pursue an innocent party
