# Extortion and monetisation

How attackers convert access, stolen data, or system control into financial
gain, regulatory pressure, or competitive advantage. Understanding these
pathways is necessary for red teams simulating realistic threat scenarios.

## The extortion model landscape

### Single extortion (legacy)

Encrypt files, demand payment for decryption. Backup restoration provides
recovery. This model's effectiveness has declined as backup practices
improved. Fewer than one in three victims pays.

### Double extortion

Exfiltrate data before encrypting. Demand payment for both the decryptor
and the deletion of the stolen data. Offline backups no longer provide full
recovery because the data is already in the attacker's possession.

### Triple extortion

Add a DDoS component targeting the victim's public-facing services during
negotiations. The operational pressure from the DDoS adds urgency to pay
quickly, before the reputational damage compounds.

### Data-only extortion

No ransomware. Steal data and threaten to publish it, submit it to regulators,
or sell it to competitors. This model has lower operational complexity
(no ransomware to deploy) and is harder for defenders to detect: there is no
encryption event to trigger an alert.

### Regulatory pressure extortion

GDPR and sector-specific regulations create financial liability for data
breaches. Attackers exploit this by threatening to report the breach to the
regulator if the victim does not pay. The regulatory fine may be larger than
the ransom demand.

## Dark web data markets

Stolen data has an established secondary market. Pricing depends on
freshness, completeness, and the identity of the victim organisation.

Typical categories and value ranges:

| Data type | Approximate value |
| --------- | ----------------- |
| Credit card with CVV | £50-£200 depending on balance and region |
| Corporate VPN or RDP credentials | £300-£2,000 per set |
| Full identity package (name, ID, address, financial) | £500-£1,500 |
| Executive email account access | £1,000-£5,000 |
| Healthcare records (patient data with insurance) | £200-£500 per record at volume |

These figures vary significantly by market and buyer. The value is also
affected by whether the victim organisation has been notified: fresh
credentials command higher prices.

## Payment and laundering

Ransomware demands are paid in cryptocurrency, typically Monero (XMR)
for its privacy properties or Bitcoin with subsequent laundering through
mixers or cross-chain bridges.

For red team simulations, payment tracking tools like Chainalysis Reactor
can be used to demonstrate to clients how real attackers would launder funds.

## Red team simulation of extortion

Red team exercises that include an extortion simulation component test:

- Whether the organisation can detect the data theft before it is weaponised
- Whether the incident response plan addresses the threat of data publication
- Whether the communications, legal, and PR functions are prepared to
  respond to a leak or regulatory threat
- Whether financial workflows are resilient to social engineering during
  an incident (attackers sometimes impersonate the victim's own IT or legal
  teams during negotiations)

The simulation stops at creating a notification that data has been exfiltrated;
no actual threat is made to publish. The goal is to test the response process,
not to create liability.

## Business impact of data-first extortion

What makes data extortion different from ransomware is the irreversibility:

- Once data is exfiltrated, it cannot be unexfiltrated
- Paying the ransom does not guarantee deletion
- The attacker may sell the data regardless of payment
- A second extortion demand for the same data is possible

For organisations that handle personal data, health data, or financial data
under regulation, a single successful exfiltration event can result in
regulatory fines, civil liability, and permanent reputational damage that
exceeds any ransom demand.
