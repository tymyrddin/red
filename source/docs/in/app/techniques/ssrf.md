# Server-side request forgery (SSRF)

A server-side request forgery (SSRF) attack forces some server-side application to make HTTP requests to a domain of
the attacker's choosing. This can sometimes grant access to internal resources or unprotected admin panels.

## Steps

1. Spot the features prone to SSRFs and take notes for future reference.
2. Set up a callback listener to detect blind SSRFs using an online service, Netcat, or Burp’s Collaborator feature.
3. Provide the potentially vulnerable endpoints with common internal addresses or the address of a callback listener.
4. Check whether the server responds with information that confirms the SSRF. For a blind SSRF, check the server logs
   for requests from the target server.
5. For a blind SSRF, check whether the server behaviour differs when different hosts or ports are requested.
6. If SSRF protection is implemented, try to bypass it by using the strategies discussed in this chapter.
7. Pick a tactic to escalate the SSRF.
8. Draft report.

## Spot features prone to SSRFs

SSRFs occur in features that require visiting and fetching external resources. These include webhooks, file uploads,
document and image processors, link expansions or thumbnails, and proxy services. It is also worth testing any endpoint
that processes a user-provided URL. And pay attention to potential SSRF entry points that are less obvious, like URLs
embedded in files that are processed by the application (XML files and PDF files can often be used to trigger SSRFs),
hidden API endpoints that accept URLs as input, and input that gets inserted into HTML tags.

## Provide potentially vulnerable endpoints with internal URLs

Once the potentially vulnerable endpoints are identified, supply internal addresses as the URL inputs. Depending on the
network configuration, several addresses may need trying before the ones in use turn up.

## Check the results

For a regular SSRF, the question is whether the server returns a response that reveals anything about the internal
service: service banners, or the content of internal pages.

The easiest way of detecting blind SSRFs is through out-of-band techniques: the target is made to send requests to an
attacker-controlled external server, and the server logs are then watched for requests from the target.

Generating an outbound request from the target server alone is not an exploitable issue. Since a blind SSRF cannot read
internal files or access internal services directly, exploitability is confirmed by exploring the internal network:
requests to various target ports, watching whether server behaviour differs between commonly open and closed ports.

## Bypassing protections

Sometimes an SSRF payload draws this response:

```text
Error. Requests to this address are not allowed. Please try again.
```

This SSRF was blocked by a protection mechanism, possibly a URL allowlist or blocklist. The site may have protection
mechanisms implemented, but this does not mean that the protection is complete.

Allowlists are generally the hardest to bypass, because they are, by default, stricter than blocklists. Getting around
them is still possible where an open redirect exists within the allowlisted domains: an allowlisted URL that redirects
to an internal URL does the job.

Since applications often need to fetch resources from a variety of internet sources, most SSRF protection mechanisms
come in the form of a blocklist. Against a blocklist, there are many ways of tricking the server.

* Fooling it with [redirects](redirects.md).
* Using IPv6 addresses.
* Tricking the server with DNS.
* Switching out the encoding.

## Escalation

SSRF can be anywhere from harmless to catastrophic. This depends on a number of factors like the visibility of the
response and which internal hosts are accessible.

What may be possible with an SSRF depends on the internal services found on the network. SSRF can maybe be used to scan
the network for reachable hosts, port-scan internal machines to fingerprint internal services, collect instance
metadata, bypass access controls, exfiltrate confidential data, and even execute code on reachable machines. At its
absolute worst, SSRF vulnerabilities could result in a full compromise of cloud environments, with internal
administrative dashboards being exposed and internal hosts being exploited.

## Variants

The basic cases reach the local server or another back-end system directly. The filtered
cases bypass a blacklist or whitelist, often by chaining an open redirect within an allowed
domain. The blind cases rely on out-of-band detection, and the payoff ranges from internal
network mapping to Shellshock execution on a reachable host. The
[server-side injection runbook](../runbooks/injection.md) covers OOB detection and internal
probing, including cloud metadata.

### Scan the network

Reachable machines are other network hosts that can be connected to via the current machine. These internal machines
might host databases, internal websites, and otherwise sensitive functionalities that can be exploited.

### Pulling AWS instance metadata

Amazon Elastic Compute Cloud (EC2), offers an instance metadata tool that enables EC2 instances to access data about
themselves by querying the API endpoint at `169.254.169.254`.

```text
http://169.254.169.254/latest/meta-data/
```

Use this URL in an endpoint vulnerable to SSRF:

```text
https://public.example.com/proxy?url=http://169.254.169.254/latest/meta-data/
```

These API endpoints are accessible by default unless network admins specifically block or disable them. The information
these services reveal is often extremely sensitive and could allow attackers to escalate SSRFs to serious information
leaks and even [RCE](rce.md).

### Google Cloud metadata

If the company uses Google Cloud, query the Google Instance Metadata API instead. Google implements additional security
measures for its API endpoints, so querying Google Cloud Metadata APIv1 requires one of these special headers:

```text
Metadata-Flavor: Google
X-Google-Metadata-Request: True
```

These headers offer protection against SSRFs because an SSRF often cannot specify special headers for the forged
request. Forging the required headers is the obstacle for instance metadata on Google Cloud targets.

### Exploiting blind SSRFs

Because blind SSRFs don’t return a response or error message, their exploitation is often limited to network mapping,
port scanning, and service discovery. Since information cannot be extracted directly from the target server, this
exploitation relies heavily on inference. Yet analysing HTTP status codes and server response times often achieves
results similar to regular SSRF.

What the network scan, service identification, and instance metadata turn up feeds attacks with impact: it may be
possible to [bypass access controls](acl.md), [leak confidential information](disclosure.md),
and [execute code](rce.md).

## Resources

* [Portswigger: Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
* [OWASP: Testing for Server-Side Request Forgery](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery)
* [OWASP: Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [EC2 API endpoints](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
* [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/)
* [Google Cloud: About VM metadata](https://cloud.google.com/compute/docs/metadata/overview)
* [Oracle Cloud: Getting Instance Metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm)

## Counter moves

Server-side request forgery (SSRF) is the case here. These come back to the same answers: validated input, encoded
output, server-side authorisation, and patched dependencies. Defenders' notes on this are
under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
