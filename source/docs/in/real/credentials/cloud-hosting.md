# Credential harvesting via legitimate cloud services

The problem with hosting a phishing page on attacker-controlled infrastructure is that the domain
is unfamiliar, the SSL certificate was issued last week, and threat intelligence feeds have probably
seen it before the campaign runs. The problem with hosting it on SharePoint, OneDrive, Google Drive,
or Dropbox is that there is no problem. The domain is trusted, the certificate is valid, the
reputation is excellent, and most email security gateways will pass a link to Microsoft or Google
infrastructure without comment.

Legitimate cloud services are increasingly used as phishing delivery infrastructure because they
provide everything an attacker needs: reliable hosting, trusted domain names, HTTPS by default,
and a CDN that ensures the page loads quickly in every geography.

## SharePoint and OneDrive

Microsoft 365 environments are the dominant target for cloud-hosted credential harvesting, partly
because they are ubiquitous and partly because the infrastructure for attacking them is, helpfully,
also Microsoft's. A SharePoint page that prompts for Microsoft credentials looks exactly like a
Microsoft credentials prompt because it is styled with the same design language, served from a
Microsoft domain, and behaves identically to a legitimate authentication request in every visible
respect.

The delivery mechanism is typically a sharing notification. SharePoint and OneDrive both send
automated emails when a document is shared, and these emails are familiar to anyone who works in
an environment that uses Microsoft 365. An attacker with a compromised or newly created tenant
can send legitimate sharing notifications pointing to a page that collects credentials before
redirecting to an actual document.

The sharing email itself is sent from Microsoft infrastructure, arrives from a Microsoft domain,
and passes authentication checks because it is technically legitimate. The only indication that
something is wrong is the destination, which most users do not examine closely before clicking.

## Google Drive and Workspace

The same principle applies to Google infrastructure. A file shared via Google Drive produces an
email notification from google.com, which is immediately trusted. The shared file can contain
a link to a harvesting page, a redirect to a credential collection form, or can itself be an
HTML file that executes in the browser when opened.

Google Forms and Google Sites provide free hosting for pages that can be styled arbitrarily,
are served from google.com subdomains, and have no particular restrictions on content short of
a content moderation process that is reactive rather than proactive. A Google Form collecting
usernames and passwords looks, to a gateway tool, like a Google Form.

## Dropbox, Box, and other platforms

File sharing platforms more broadly follow the same pattern. Any platform that allows arbitrary
file uploads and generates sharing links will serve as a vector. The specific value varies by
target: a Dropbox link is more plausible in a creative or marketing context, a Box link is more
plausible in a financial or legal context, and both carry the trust of an established brand.

Some platforms allow HTML file uploads that render in the browser with full CSS and JavaScript.
These can be styled to match any expected service and provide a functional credential collection
page hosted entirely on trusted infrastructure, with a valid certificate and no malicious domain
in sight.

## Operational notes

The most effective cloud-hosted harvesting campaigns combine platform trust with a believable
pretext. A link to a shared document that requires sign-in is plausible in any professional
context. A link to a document that appears to contain something the target cares about, budgets,
contracts, personnel information, security reports, is more likely to be clicked before the
URL is examined.

Chaining platforms adds layers of redirection. An email link pointing to a clean Google Drive
document that contains a link to a harvesting page on another service puts more distance between
the initial delivery and the malicious endpoint, and makes retrospective analysis of the campaign
more complicated.

## Runbooks

- [Runbook: AiTM phishing with Evilginx2](../runbooks/aitm-phishing.md) — legitimate cloud infrastructure is the delivery mechanism in this playbook's phishing phase
- [Runbook: Quishing campaign](../runbooks/quishing-campaign.md) — the harvesting page can be hosted on cloud infrastructure as described here
