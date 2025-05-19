# SMTP enumeration

SMTP provides three built-in commands:

* VRFY: Validate users on the SMTP servers
* EXPN: Delivery addresses of aliases and mailing lists
* RCPT TO: Defines the recipients of the message

SMTP servers respond differently to the commands mentioned above, and SMTP enumeration is possible due to varied responses. Attackers can determine the valid users on the SMTP servers with the same technique.

## Tools

* [smtp-user-enum](https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum) is a username guessing tool primarily for use against the default Solaris SMTP service.
* Metasploit provides two SMTP auxiliary Modules i.e., `smtp_enum` and `smtp_version`. Both are used for SMTP enumeration and provide adequate information about the SMTP server. 
* nmap provides special scripts for SMTP enumeration. `smtp-enum-users` is one of the scripts that is provided by Nmap.

## Remediation

* Ignore email responses from unknown recipients.
* Disable open relay functionality.
* Prune any sensitive information like mail server and localhost in the mail responses.
