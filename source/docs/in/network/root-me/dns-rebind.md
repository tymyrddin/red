# HTTP - DNS Rebinding

TTL=0 (probably a hint). Challenge at rootme: https://www.root-me.org/en/Challenges/Network/HTTP-DNS-Rebinding.

## Statement

The devops of this small web application don’t have a lot of time and even fewer resources. The administration 
interface is thus, as is often the case, embedded within the UI. However, they did make sure that it cannot be 
accessed from the outside...

Source code is given. And https://crypto.stanford.edu/dns/dns-rebinding.pdf

***

## Source code analysis

The challenge involves a Python web application with these key components:

* An admin interface at `/admin` only accessible from localhost (127.0.0.1)
* A URL grabber endpoint at `/grab` that fetches external URLs after validation
* The validation checks if the domain resolves to a global IP (not LAN)
* The hint "TTL=0" suggests DNS records can change quickly

## Attack strategy

Do a DNS rebinding attack to:

* Make the server request its own admin page
* Bypass the IP restriction by changing DNS resolution mid-request
* Have the server include its own auth token in the request

## Flow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                                                                               │
│                          DNS REBINDING ATTACK FLOW                            │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
│             │       │                       │       │                       │
│   ATTACKER  ├───────►  CHALLENGE SERVER    ├───────►  DNS RESOLVER          │
│             │   (1) │  (grabs URL content)  │   (2) │  (checks domain)      │
└─────────────┘       └───────────┬───────────┘       └───────────┬───────────┘
                                  │                               │
                                  │                               │
┌─────────────┐       ┌───────────▼───────────┐       ┌───────────▼───────────┐
│             │       │                       │       │                       │
│  MALICIOUS  │       │  FIRST DNS LOOKUP:    │       │  SECOND DNS LOOKUP:   │
│   DOMAIN    │       │  PUBLIC IP (VALID)    │       │  127.0.0.1 (REBIND)   │
│             │       │                       │       │                       │
└─────────────┘       └───────────────────────┘       └───────────────────────┘
                                  │                               │
                                  │                               │
┌─────────────┐       ┌───────────▼───────────┐       ┌───────────▼───────────┐
│             │       │                       │       │                       │
│   FLAG!     ◄───────┤ SERVER FETCHES ADMIN  ◄───────┤ REQUEST TO LOCALHOST  │
│             │       │  PAGE WITH OWN TOKEN  │       │  WITH VALID TOKEN     │
└─────────────┘       └───────────────────────┘       └───────────────────────┘

KEY:
(1) GET /grab?url=http://malicious-domain.com/admin
(2) DNS Query for malicious-domain.com
```

Detailed steps shown in the flow:

1. Attacker sends crafted URL to challenge server
2. Server performs initial DNS lookup (gets public IP)
3. Server makes request to what it thinks is external site
4. DNS rebinding occurs - domain now resolves to 127.0.0.1
5. Server unknowingly requests its own admin page
6. Server includes its valid auth token in request
7. Admin page returns flag to attacker through response chain

## Set up DNS rebinding infrastructure

The most reliable way is setting up your own DNS server with rebinding capabilities. The GitHub project rbndr 
by taviso provides a simple, non-conforming name server for testing DNS rebinding vulnerabilities.

1. Clone the repository: git clone https://github.com/taviso/rbndr
2. Configure it to alternate between IP addresses
3. Set very low TTL values (0-1 second)

## Craft the exploit url

Construct a URL that will initially resolve to a public IP (passing validation), then resolve to 127.0.0.1 when the 
server makes the request:

```
http://challenge01.root-me.org:54022/grab?url=http://your-rebinding-domain/admin
```

## Go Go Go 

* Send the crafted URL to the server
* The validation will check the domain and see a public IP
* When the server makes the actual request:

    1. The DNS will resolve to 127.0.0.1
    2. The server will include its rm-token header automatically
    3. The request will reach the admin interface locally
    4. The response (with flag) will be returned to you

## Retrieve the flag

The server will return the admin page contents including the flag in the response.

## Reality

* Many public DNS services now block private IP resolutions by default due to security concerns
* Modern browsers have implemented stronger protections against DNS rebinding
* IPv6 introduces new rebinding possibilities that were not available in earlier years
