WebSocket vulnerabilities
===============================================================

.. image:: /_static/images/pal.png
   :alt: Portswigger Academy Websockets Labs
   :target: https://portswigger.net/web-security/all-labs#websockets

WebSockets are widely used in modern web applications. They are initiated over HTTP and provide long-lived connections
with asynchronous communication in both directions.

WebSocket vulnerabilities are increasingly common due to the rise of real-time apps (chat, trading, gaming, and IoT
dashboards). While not as widespread as XSS or SQLi, they appear in ~15-25% of apps using WebSockets (based on pentests
and bug bounty reports).

They are a growing target because they maintain persistent connections, increasing attack surface, have no automatic
CSRF/CORS protections like HTTP and misconfigurations. Developers often forget authentication/authorization checks,
input validation on WebSocket messages, and rate limiting (leading to DoS).

They can lead to authentication bypass (e.g., connecting without a valid session), data Interception
(missing TLS → MITM attacks), business logic flaws (e.g., spoofing trades in a stock app), and Denial-of-Service (DoS)
(flooding WebSocket connections).

Testing for it makes sense if the app uses WebSockets for real-time features (chat, notifications, live updates), if
it is a financial app (trading, crypto, payments), and in the context of IoT/device control (e.g., smart home
dashboards).

.. toctree::
   :glob:
   :maxdepth: 1
   :includehidden:
   :caption: If an app uses WebSockets, test them as rigorously as APIs:

   1.md
   2.md
   3.md
