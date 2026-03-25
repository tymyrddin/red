# Runbook: GCP project and bucket enumeration

Google Cloud Platform organises resources under projects, which have globally unique project IDs. Those IDs
appear in API responses, error messages, and public documentation, making them useful anchors for enumeration.
Cloud Storage buckets on GCP follow the same globally unique naming pattern as S3, and misconfigured public
access is still common.

## Objective

Identify GCP projects associated with the target organisation. Enumerate accessible Cloud Storage buckets.
Discover Firebase databases and other GCP services that are publicly reachable.

## Prerequisites

- Target organisation name and domain.
- `gsutil` and `gcloud` CLI installed.
- `curl` for direct API calls.
- Wordlists for bucket and project name permutations.

## Phase 1: Project ID discovery

GCP project IDs appear in multiple public sources.

Search GitHub repositories associated with the organisation for project ID patterns:

```bash
grep -r "gcp-project" .
grep -r "project_id" .
grep -r "google-cloud" .
grep -r "googleapis.com" .
```

Search Shodan and Censys for GCP-hosted infrastructure using the organisation's domain and certificate
subjects. GCP compute instances and App Engine services use certificates that include the application
URL, which often contains the project ID:

```
ssl:"target.com" org:"Google"
```

Error messages from GCP-hosted applications sometimes include the project ID directly, particularly
from Cloud Functions, App Engine, and Cloud Run.

## Phase 2: Cloud Storage bucket enumeration

GCP bucket names are globally unique and DNS-compatible. The access check is a simple HTTP request:

```bash
# Check for public listing
curl -s "https://storage.googleapis.com/BUCKET-NAME/"

# Using gsutil without credentials
gsutil ls gs://BUCKET-NAME/
```

A `200` response with XML content means the bucket exists and listing is enabled for the public.
A `403` response means the bucket exists but is not publicly listable.
A `404` response means no bucket with that name exists.

Generate permutations from the organisation name and test each:

```bash
for name in target target-backup target-prod target-dev target-data target-assets target-static; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$name/")
  echo "$name: $status"
done
```

For any bucket that responds with `200` or `403`, enumerate the contents if public:

```bash
gsutil ls -r gs://BUCKET-NAME/
```

Look for the same categories as in S3 discovery: configuration files, credential files, database dumps,
application builds, and log files.

## Phase 3: Firebase database discovery

Firebase Realtime Databases are accessible via a predictable URL pattern:

```
https://PROJECT-ID-default-rtdb.firebaseio.com/.json
```

If the database has public read rules enabled, the `.json` endpoint returns the entire database contents.

Common project ID patterns for Firebase:

```bash
for suffix in "" "-default" "-prod" "-dev" "-app"; do
  url="https://target${suffix}-default-rtdb.firebaseio.com/.json"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  echo "$url: $status"
done
```

A `200` response means the database exists and is publicly readable. A `401` means it exists but
requires authentication. A `404` or connection refused means it does not exist.

Firebase Firestore does not have a direct HTTP enumeration path but is accessible via the REST API
if the security rules permit unauthenticated reads:

```bash
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT-ID/databases/(default)/documents/COLLECTION"
```

## Phase 4: App Engine and Cloud Run discovery

App Engine services are hosted on `PROJECT-ID.appspot.com` and sometimes on custom domains. Check
whether the default App Engine URL is live:

```bash
curl -s -o /dev/null -w "%{http_code}" "https://PROJECT-ID.appspot.com/"
```

Cloud Run services are hosted on `SERVICE-REGION.run.app`:

```bash
curl -s -o /dev/null -w "%{http_code}" "https://SERVICE-REGION.run.app/"
```

Both may expose unauthenticated endpoints if IAM is not configured to require authentication. Cloud Run
services that allow `allUsers` to invoke the service are accessible from the internet.

## Phase 5: GCP service account key exposure

Service account key files for GCP are JSON files with a characteristic structure. Search GitHub and
public repositories for these:

```bash
grep -r '"type": "service_account"' .
grep -r "private_key_id" .
grep -r "client_email.*iam.gserviceaccount.com" .
```

A valid service account key file grants access to whatever resources the service account's IAM roles
cover. Test key validity with:

```bash
gcloud auth activate-service-account --key-file=key.json
gcloud projects list
```

If `gcloud projects list` returns projects, the key is valid and the service account has at least
`resourcemanager.projects.list` permission.

## Output

- Project IDs discovered and confirmed.
- Cloud Storage buckets with URL and access control status.
- Firebase databases found, with data summary if publicly readable.
- App Engine and Cloud Run endpoints discovered.
- Service account key files found in public repositories.

## Playbooks

- [Cloud initial access](../playbooks/cloud-entry.md)