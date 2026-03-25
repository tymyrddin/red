# Mass assignment

Mass assignment occurs when an API binds request body fields directly to a data model without
restricting which fields are writable. A caller who knows (or discovers) the name of a field that
should be read-only can set it by including it in a request body.

## How it works

Most modern frameworks provide a convenience pattern for updating model attributes from request
input: pass the parsed request body to the ORM's update method and the framework maps fields by
name. This is efficient for development. The security assumption is that the model only exposes
safe fields. When that assumption is wrong, because the model has fields like `role`, `is_admin`,
`balance`, or `status` that the developer did not intend to be user-settable, the pattern becomes
a vulnerability.

The attacker does not need to know these fields in advance. They can be discovered by reading the
API responses (which show all model attributes), reading the API documentation or specification,
or fuzzing the request body with likely field names.

## Common targets

Account privilege fields are the most impactful: `role`, `is_admin`, `admin`, `permissions`,
`account_type`. Setting any of these to an elevated value during a profile update or registration
request can produce immediate privilege escalation.

Financial fields: `balance`, `credits`, `subscription_tier`, `trial_expires_at`. Setting these
directly can produce financial impact without requiring access to the payment processing flow.

Status fields: `is_verified`, `email_confirmed`, `kyc_status`. Bypassing verification workflows
by setting the completion state directly.

## Detection

Add extra fields to any request body that creates or modifies a record and observe whether they
appear in subsequent responses. The most efficient approach is to include all fields visible in
the API's response objects for the same resource type in a write request for that resource.

## Runbooks

- [REST API attack chain](../playbooks/rest-api.md) — mass assignment is tested in Phase 5
