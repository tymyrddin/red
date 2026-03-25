# Runbook: Object storage discovery

Object storage (S3 on AWS, Blob on Azure, Cloud Storage on GCP) is consistently one of the most productive
cloud recon targets. Misconfigured buckets and containers expose data without any credential requirement,
and the naming conventions used make discovery straightforward.

## Objective

Find storage resources belonging to the target organisation. Determine which are publicly accessible.
Document what is readable and, where scope permits, what the accessible content reveals.

## Prerequisites

- Target organisation name, domain, and any known brand names or subsidiary names.
- AWS CLI installed and configured (even without credentials, for unauthenticated checks).
- Wordlists for bucket name permutations.
- GrayhatWarfare account for passive search.

## Phase 1: Passive discovery

Start without making requests to AWS, Azure, or GCP directly.

Search Google for buckets and containers linked to the target:

```
site:s3.amazonaws.com "target"
site:amazonaws.com "target"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
```

Search GrayhatWarfare for known public buckets:

```
https://buckets.grayhatwarfare.com/
```

Search certificate transparency logs for bucket-style hostnames:

```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | jq -r '.[].name_value' \
  | grep -E "(s3|blob|storage|backup|data|assets|static)"
```

Search GitHub repositories associated with the organisation for S3 URLs and bucket names:

```bash
# in the target's repositories, search for bucket references
grep -r "s3://" .
grep -r "amazonaws.com" .
grep -r "blob.core.windows.net" .
```

## Phase 2: Name permutation

If no bucket names are found passively, generate permutations from the organisation name and common suffixes.
Buckets are globally unique and named by the organisation: they almost always include the company name,
product name, or project name combined with an environment or purpose indicator.

Common patterns:

```
target-backup
target-prod
target-dev
target-staging
target-assets
target-data
target-logs
target-static
target.com
target-internal
target-uploads
```

Use Lazys3 to automate permutation checking:

```bash
python3 lazys3.py target
```

Use Bucket Stream to find buckets based on certificate transparency data:

```bash
python3 bucket-stream.py --target target.com
```

## Phase 3: Access verification

For each candidate bucket or container, verify existence and access level.

### AWS S3

Check whether the bucket exists and whether it allows unauthenticated listing:

```bash
aws s3 ls s3://bucket-name/ --no-sign-request
```

A successful listing means public read on the bucket prefix. Check individual files:

```bash
aws s3 cp s3://bucket-name/interesting-file.txt . --no-sign-request
```

Test whether unauthenticated write is permitted:

```bash
echo "test" > probe.txt
aws s3 cp probe.txt s3://bucket-name/probe.txt --no-sign-request
# If successful, remove the file
aws s3 rm s3://bucket-name/probe.txt --no-sign-request
```

### Understanding S3 URL formats

Virtual-hosted style (most common):

```
https://bucket-name.s3.amazonaws.com/
https://bucket-name.s3.REGION.amazonaws.com/
```

Path style (older, still used):

```
https://s3.amazonaws.com/bucket-name/
https://s3.REGION.amazonaws.com/bucket-name/
```

The `us-east-1` region uses `s3.amazonaws.com` and `s3-external-1.amazonaws.com` interchangeably.
Frankfurt (`eu-central-1`) and Seoul (`ap-northeast-2`) accept both `s3-REGION.amazonaws.com` and
`s3.REGION.amazonaws.com`.

Presigned URLs grant time-limited unauthenticated access to specific objects. If a presigned URL is
found (in source code, emails, or support documentation), test whether it is still valid and what it
exposes. Presigned URLs expire at a set time but are sometimes issued with very long validity windows.

Static website hosting endpoints follow a different pattern:

```
http://bucket-name.s3-website-REGION.amazonaws.com
http://bucket-name.s3-website.REGION.amazonaws.com  # eu-central-1, ap-northeast-2
```

### Azure Blob

Container URL pattern:

```
https://storageaccountname.blob.core.windows.net/containername/
```

Check for public anonymous access:

```bash
curl -s "https://storageaccountname.blob.core.windows.net/containername?restype=container&comp=list"
```

An XML listing response means public access. A `ResourceNotFound` or `PublicAccessNotPermitted` response
means the container exists but is not public.

### GCP Cloud Storage

GCP bucket URL:

```
https://storage.googleapis.com/bucket-name/
```

Check for public listing:

```bash
curl -s "https://storage.googleapis.com/bucket-name/"
```

Or using `gsutil` without credentials:

```bash
gsutil ls gs://bucket-name/
```

## Phase 4: Content triage

If a bucket is publicly readable, triage its contents before downloading anything.

List top-level keys to understand the structure:

```bash
aws s3 ls s3://bucket-name/ --no-sign-request
aws s3 ls s3://bucket-name/ --recursive --no-sign-request | head -100
```

Look specifically for:

- Configuration files: `.env`, `config.yml`, `settings.json`, `*.conf`, `*.cfg`
- Credential files: `credentials`, `*.pem`, `*.key`, `*.pfx`, `id_rsa`
- Database dumps: `*.sql`, `*.dump`, `*.bak`
- Archive files containing any of the above: `*.zip`, `*.tar.gz`
- Application builds that may contain hardcoded secrets
- Log files that contain tokens, session identifiers, or internal hostnames

## Output

- List of discovered buckets and containers with URL, provider, and access control status.
- Contents summary for any accessible storage: file count, file types, size.
- Any sensitive files found: credentials, configuration, database content.
- Write access findings, with evidence preserved and any test files removed.
- Presigned URLs found in other sources, with validity status.

## Playbooks

- [Cloud initial access](../playbooks/cloud-entry.md)