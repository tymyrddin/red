# Monitoring

Collectors tell you what the table holds; monitors tell you when it changes, while
you are looking elsewhere. The hijack anyone catches is usually the one something
was already watching for. Most of this is configure-once: name the prefixes you
care about, the origins that may announce them, and let the tool ring a bell on
anything else.

## BGPalerter, the one you run yourself

[BGPalerter](https://github.com/nttgin/BGPAlerter) is the open-source standout. It
reads RIS Live, watches the prefixes you list, and alerts on the things that count:
a new origin (a hijack), a more-specific you did not announce, lost visibility, an
unexpected upstream, an expiring or invalid ROA. It runs locally, needs no account,
and will write a starting config from your ASN:

```bash
bgpalerter generate -a 65020 -o prefixes.yml
```

```yaml
# prefixes.yml
203.0.113.0/24:
  description: the prefix we care about
  asn:
    - 65020
  ignoreMorespecifics: false
```

Point it at a webhook, Slack, email or syslog, and it becomes the bell.

## The dashboards

For a view without running anything, the hosted ones. [Cloudflare Radar](https://radar.cloudflare.com) tracks route
leaks and origin hijacks at internet scale; [bgp.tools](https://bgp.tools/) offers per-prefix monitoring and alerts on an
account; RIPEstat and RIPE Atlas cover routing and reachability. The commercial tier (Kentik, ThousandEyes,
Qrator.Radar, Catchpoint) adds depth and support for those who pay.

## What to watch for

The signals worth an alert are few and stable: a prefix announced by an origin that
should not announce it, a more-specific you did not originate, a sudden change of
upstream, and visibility that drops in one region but not others. Everything
fancier is a refinement on those four.
