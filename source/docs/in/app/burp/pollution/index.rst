Prototype pollution
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Prototype pollution Labs
   :target: https://portswigger.net/web-security/all-labs#prototype-pollution

Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global
prototypes, which may then be inherited by user-defined objects.

Prototype pollution remains a stealthy but dangerous threat, affecting JavaScript-heavy applications (based on bug
bounty reports and pentests). It is less frequent than XSS or SQLi, but high-impact when exploited, especially in
modern JS frameworks (React, Angular, Vue), APIs/cloud functions (Node.js, serverless backends), and libraries/tools
(e.g., lodash, jQuery, and custom utilities).

It is still relevant due to merging user input into objects without sanitisation is still common, the possibility for
silent exploitation (RCE in Node.js if polluted properties reach `child_process` or `eval()`, DOM XSS Escalation
polluting `Object.prototype`, or Arbitrary Property Injection overwriting sensitive attributes (e.g., `isAdmin: true`)),
and many SAST tools missing prototype pollution unless explicitly configured.

It is worth testing for when the app uses dynamic object manipulation (e.g., `Object.assign`, `merge`,
`lodash.defaultsDeep`), you see user input passed to `JSON.parse()` or object utilities, and/or the app relies on
client-side JS frameworks (e.g., admin dashboards, SPAs).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: Prioritise testing in JavaScript-heavy apps (SPAs, Node.js backends) and apps using `lodash`, `jQuery.extend`, or custom merges:


   1.md
   2.md
   3.md
   4.md
   5.md
   6.md
   7.md
   8.md
   9.md
   10.md

