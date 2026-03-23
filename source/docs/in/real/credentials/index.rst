Getting past the login page
============================

Stealing a password used to be most of the job. Now it is often just the beginning of a longer conversation with
whatever multi-factor authentication the organisation has bolted on. The techniques in this section cover how
attackers harvest credentials using infrastructure the target already trusts, how they deal with the second factor,
and how they obtain persistent access to cloud environments without ever learning anyone's password at all.

The common thread is that modern authentication is not as robust as it looks from the outside. It was designed for
convenience as much as security, and those two things have not always pulled in the same direction.

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Credential harvesting and authentication bypass

   cloud-hosting.md
   mfa-bypass.md
   consent-phishing.md
