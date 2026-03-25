The device is just the keyring
======================================================

.. image:: /_static/images/endpoint.png
   :alt: A laptop open on a desk, screen glowing, surrounded by floating keys, browser tabs, and cloud icons dissolving into smoke. The device looks untouched. The identity has already left.

The endpoint is no longer the prize. It is the threshold. Attackers learned years ago that owning the box is the noisy
way to do things: EDR fires, analysts wake up, containment happens. The quiet way is to borrow the session, pocket the
token, and let the legitimate user's identity do the work. No blue screen. No ransom note. Just someone else's browser
cookies accessing the cloud console at 2am from an IP that resolves to a residential proxy.

Modern endpoint compromise is an identity operation wearing an endpoint's clothes. The device holds the credentials,
the browser holds the sessions, the cloud holds the data, and the attacker needs only a thread connecting all three.
EDR evasion is a discipline now, fileless execution is the default, and the most dangerous payloads are the ones
that look indistinguishable from the user they impersonate.

.. toctree::
   :glob:
   :maxdepth: 2
   :includehidden:
   :caption: Own the identity, not the box:

   notes/index
   runbooks/index
   playbooks/index
