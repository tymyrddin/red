# Reduce API attack surface

APIs have a larger attack surface than most organisations realise because that surface is not just
the documented endpoints. It includes deprecated versions, undocumented internal endpoints, exposed
schemas, and the credentials that grant access to all of it. Reducing the surface means treating
all of these as things that require active management rather than things that exist by default.

## Schema and documentation exposure

### Disable introspection in production

GraphQL introspection is a development convenience. In production it hands the complete schema to
anyone who asks. Disable it at the application level, not just by removing the documentation link:

```python
# Apollo Server (Node.js)
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
});
```

```python
# Graphene (Python/Django)
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': [],
}
# In the view:
GraphQLView.as_view(graphiql=False, schema=schema)
```

Test that introspection is actually disabled after deployment, not just that the documentation
page is gone. The introspection query and the documentation UI are independent.

### Remove OpenAPI specifications from production

OpenAPI and Swagger specifications should be served only in development and staging environments.
If external API consumers need documentation, publish a curated subset via an API portal, not the
full internal specification.

If the specification must be accessible, require authentication to retrieve it. An unauthenticated
`/swagger.json` describes the complete attack surface to anyone who checks.

### Suppress verbose error messages

Framework-level error handlers in production should return generic error responses, not stack
traces or field validation details that describe internal structure. Validation errors should tell
the caller that their input was invalid, not which field failed which constraint.

Configure production error handlers to catch unhandled exceptions and return a generic `500`
response body. Log the full error server-side.

## Authentication controls

### Enforce authentication by default

Every endpoint should require authentication unless explicitly marked as public. A framework-level
middleware that requires a valid token and returns `401` when none is present is safer than
per-endpoint opt-in authentication checks that can be forgotten.

Periodically audit every endpoint against the authenticated-by-default configuration. Automated
tests that call every endpoint without credentials and assert a `401` response are the most
reliable way to catch regressions.

### JWT hardening

Reject tokens with the `none` algorithm unconditionally. Explicitly allowlist the algorithms the
API accepts rather than accepting whatever the token header declares:

```python
jwt.decode(token, secret, algorithms=["HS256"])  # not algorithms=jwt.algorithms.get_default_algorithms()
```

Use strong signing keys: at least 256 bits of entropy for HMAC, at least 2048-bit RSA for
asymmetric signing. Store signing keys in a secrets manager, not in application configuration
files or environment variables committed to source control.

Set short expiry times on access tokens. Fifteen minutes to one hour is appropriate for most
use cases. Issue refresh tokens separately with longer lifetimes and revocation support.

### API key management

Treat API keys as credentials with a full lifecycle: issuance, rotation, and revocation.

- Issue keys with the minimum permissions required for the specific integration.
- Set expiry dates on all keys; do not issue keys that never expire.
- Log every key issuance and revocation event.
- Alert on keys that have not been used for an extended period (likely abandoned and
  forgotten rather than deliberately inactive).
- Scan source code repositories continuously for committed keys.

## Authorisation controls

### Enforce authorisation at the resolver level

Object-level authorisation checks must happen at the function that returns the object, not only
at the route or controller level. A check at the route level that confirms the user is
authenticated does not confirm that the specific resource being requested belongs to them.

For every data-returning function, the check is: does the authenticated identity have permission
to access this specific record? That check must be explicit, not implicit.

### Avoid direct object references in URLs

Predictable, sequential IDs in URLs (`/api/v1/users/1234`) make BOLA testing trivial. UUIDs or
opaque identifiers slow enumeration but do not prevent it if authorisation checks are absent.

The correct control is the authorisation check. The identifier format is an additional layer, not
a substitute.

### Restrict mass assignment

Explicitly define which fields a request body is permitted to set. Do not pass raw request body
objects to ORM update functions. An allowlist of writable fields at the model or schema level
prevents callers from setting fields like `role`, `is_admin`, or `credits` even when those fields
exist on the underlying object.

## Rate limiting and quota

Apply rate limits at the API gateway or middleware level for all endpoints. Authentication endpoints
require tighter limits than data retrieval endpoints.

Rate limits should be applied per authenticated identity, not per IP address. IP-based rate limits
are bypassed with `X-Forwarded-For` header manipulation if the API trusts that header without
validation. Only trust forwarded IP headers from known proxy infrastructure.

For GraphQL APIs, implement query depth and complexity limits:

```javascript
const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
    validationRules: [
        depthLimit(7),
        createComplexityLimitRule(1000),
    ],
});
```
