# Business process attacks

Fraud and disruption via legitimate workflow abuse. These attacks exploit
the processes organisations use to run their operations: payment approvals,
payroll, procurement, and SaaS workflow automation. No malware is required;
the attacker operates inside the system as if they were an authorised user.

## Why defenders miss this

Security monitoring is built around detecting technical attack patterns:
unusual process trees, malicious file hashes, C2 beacons. Business process
abuse generates none of these signals. A legitimate user changing a bank
account number in the HR system looks identical to a compromised identity
doing the same thing. Detection requires understanding what the business
process should look like and identifying deviations from that.

Most security teams do not have visibility into SaaS business workflows.
The finance system, HR platform, and procurement tool are often outside the
SOC's monitoring scope.

## Invoice manipulation

Accounts payable processes move significant sums. Manipulating an invoice
in transit or in the document management system redirects payments to
attacker-controlled accounts.

Attack paths:

- Intercept invoices in email and modify payment details before forwarding
  to the approver (requires mail access)
- Access the accounts payable SaaS platform and modify payment details in
  pending invoices
- Modify invoice templates in the document management system, affecting
  future invoices generated from those templates
- Send fraudulent invoices from a compromised supplier email account

```python
# example: modify a PDF invoice in transit using pikepdf
import pikepdf, re

with pikepdf.open('original_invoice.pdf') as pdf:
    for page in pdf.pages:
        if '/Resources' in page:
            # extract and modify the content stream
            # (full implementation requires PDF stream manipulation)
            pass
    pdf.save('modified_invoice.pdf')

# more practical: edit the source document if accessible
# (SharePoint, Google Drive, document management system)
```

## Payroll diversion

HR and payroll systems store employee bank account details. An attacker
with access to the HR platform can alter these details to redirect salary
payments.

Attack path:
1. Gain access to HR SaaS platform (via compromised HR employee identity)
2. Identify high-value targets (executives, large salaries)
3. Modify bank account details for the target employees
4. Wait for the next payroll run

Detection is often delayed because employees do not notice a missed payment
immediately, and the change may have been made weeks before the next run.

## SaaS workflow abuse

Modern organisations automate business processes using SaaS tools like
Zapier, Make (formerly Integromat), or native workflow features in Salesforce,
ServiceNow, and similar platforms. These workflows run with elevated
permissions and often move sensitive data automatically.

Attack paths:

- Modify an existing workflow to redirect data to an attacker-controlled
  webhook or email address
- Add a step to an existing workflow that exfiltrates trigger data
- Create a new workflow that auto-approves expense reports or purchase orders

```javascript
// Zapier webhook: data sent to this endpoint is logged
// an attacker modifies a workflow's "destination" to point here
// then watches data arrive from the target's business processes
// (no example shown; this is conceptual)
```

## Wire transfer fraud via business email compromise

Business email compromise (BEC) targets employees with authority to initiate
payments:

1. Gain access to a senior executive's or finance director's email account
2. Monitor email for context on pending financial transactions
3. Send a payment instruction to the finance team from the executive's account
4. Request urgent wire transfer to an attacker-controlled account
5. If challenged, provide a plausible business justification sourced from
   the monitored emails

This requires no technical exploitation beyond the initial identity compromise.
The average BEC loss is higher than the average ransomware payment.

## Procurement fraud

Organisations with large procurement budgets run approval workflows in
procurement systems. Inserting fraudulent purchase orders or modifying
approved vendors' payment details follows the same pattern as invoice
manipulation.

## What red teams test

A business process engagement should answer:

- Can we modify a pending invoice without triggering an alert?
- Can we change a payroll bank account record?
- Can we initiate a wire transfer from a compromised executive identity?
- Can we modify an approval workflow to auto-approve our own requests?
- How long does it take the organisation to detect a fraudulent transaction?
- Does the detection come from security monitoring or from a human noticing
  the money is missing?

The answers reveal gaps between technical security and financial control
that most organisations have not mapped.
