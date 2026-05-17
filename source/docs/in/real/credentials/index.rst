Getting past the login page
============================

Identity systems are mechanisms for delegating authority. Authentication looks like a technical process, but at
its base it is a human trust transaction mediated by software. A password is compliance with an agreement. A
session token is a consent artefact: evidence that the trust transaction happened once, portable until revoked.
An OAuth flow is a structured persuasion channel: the system presents a permission request and waits for the
human to approve it. A device authorisation flow is the same transaction displaced across contexts, with the
human making a trust decision in one place that has consequences somewhere else entirely.

The techniques in this section operate within these designed interaction patterns rather than against them.
Hosting a phishing page on SharePoint, bombing a push notification channel, obtaining a device authorisation
token through a convincing email: in each case, the protocol completes correctly. The gap is between what the
protocol records and what the person clicking understood themselves to be approving.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:

   cloud-hosting.md
   mfa-bypass.md
   consent-phishing.md
   device-code.md
