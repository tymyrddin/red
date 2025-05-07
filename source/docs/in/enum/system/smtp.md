# SMTP enumeration

SMTP provides three built-in commands:

* VRFY: Validate users on the SMTP servers
* EXPN: Delivery addresses of aliases and mailing lists
* RCPT TO: Defines the recipients of the message

SMTP servers respond differently to the commands mentioned above, and SMTP enumeration is possible due to varied responses. Attackers can determine the valid users on the SMTP servers with the same technique.

## Tools

* [SMTP enumeration tools](https://testlab.tymyrddin.dev/docs/enum/smtp)

## Remediation

* Ignore email responses from unknown recipients.
* Disable open relay functionality.
* Prune any sensitive information like mail server and localhost in the mail responses.
