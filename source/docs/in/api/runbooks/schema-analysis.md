# Runbook: Schema analysis

API schemas describe the complete structure of an API: every operation, every type, every field, and
the relationships between them. When a schema is available, it eliminates most guesswork from endpoint
and parameter discovery. When it is not available, it can often be reconstructed from observed traffic.

## Objective

Obtain or reconstruct the complete API schema. Understand every operation the API supports, the
data types it expects and returns, and the authentication requirements for each operation.

## Prerequisites

- Endpoint list from the discovery runbook.
- Burp Suite for traffic proxying and response analysis.
- Postman for importing OpenAPI and WSDL specifications.
- GraphQL Voyager or InQL for GraphQL schema visualisation.
- A GraphQL client (Insomnia or GraphQL Playground) for introspection queries.

## OpenAPI and Swagger specifications

### Retrieving the specification

If the API exposes an OpenAPI specification, retrieve it completely. The full specification is
more useful than the rendered documentation because it includes field types, validation rules,
required versus optional parameters, and sometimes example values.

```bash
curl -s https://target.com/openapi.json | python3 -m json.tool > openapi.json
curl -s https://target.com/swagger.yaml > swagger.yaml
```

Check the specification version field (`openapi: 3.0.x` or `swagger: "2.0"`). Version 3 specs
include more detail about authentication schemes and are more likely to describe server-side
validation rules.

### Importing into Postman

In Postman: File > Import > select the downloaded specification file. Postman generates a
collection with one request per operation, pre-populated with parameter names and example values.

Review the generated collection immediately for:
- Operations marked as deprecated in the spec that may still be live
- Operations with no authentication requirement listed
- Operations that accept file uploads
- Operations with `additionalProperties: true` in their request schema (mass assignment risk)
- Internal or administrative operations that appear in the spec but are not linked from the UI

### What the spec does not tell you

The specification describes the intended behaviour. Actual behaviour often differs. Parameters
not listed in the spec are sometimes accepted. Fields marked as read-only are sometimes writable.
Operations marked as requiring authentication sometimes do not enforce it.

Treat the spec as a starting point, not a complete description.

## GraphQL introspection

### Running the introspection query

GraphQL introspection returns the complete schema: every type, every field on every type, every
query and mutation, and the input types they accept.

Send this query to the GraphQL endpoint:

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }"}'
```

For the full schema including directives and deprecation information:

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}
EOF
```

Save the full response. It is the complete map of everything the API can do.

### Visualising the schema

Paste the introspection response into GraphQL Voyager to get a visual graph of types and their
relationships. This makes it much easier to identify the resources that are worth targeting and
the relationships between them.

InQL (Burp Suite extension) generates a structured list of all queries and mutations with their
parameters, directly importable into Burp's Repeater:

```bash
# Install InQL
pip3 install inql

# Generate queries from introspection
inql -t https://target.com/graphql -o output/
```

### When introspection is disabled

If introspection returns an error (`"Cannot query field __schema"`), introspection has been
disabled. This is not the end.

Clairvoyance extracts the schema from error messages returned by the API when queried with unknown
field names. It works by systematically guessing field names and observing which ones the API
accepts or rejects:

```bash
python3 -m clairvoyance -t https://target.com/graphql -o schema.json
```

Observe traffic through the application with the proxy. Every query and mutation the frontend
makes reveals fields and types. Over several sessions covering all application functionality,
the schema becomes reconstructable from observed traffic alone.

## SOAP and WSDL

SOAP services expose their complete interface description in the WSDL. Retrieve it by appending
`?wsdl` to the service endpoint:

```bash
curl -s "https://target.com/services/UserService?wsdl" > userservice.wsdl
```

The WSDL describes every operation the service offers, the message format for request and
response, and the data types used. It is the equivalent of the OpenAPI spec for SOAP.

Import the WSDL into SoapUI or Postman (which supports SOAP requests) to generate a test
collection. SoapUI generates example requests for every operation automatically.

Pay specific attention to SOAP operations that:
- Accept user-supplied identifiers (BOLA risk)
- Process file content
- Accept XML with no schema validation (XXE risk)
- Return different amounts of data depending on the caller's apparent role

## Schema reconstruction from traffic

When no specification is available and introspection is disabled, reconstruct the schema from
observed traffic.

Route all application traffic through Burp Suite and use the application extensively. After
collecting a representative sample of traffic, use Burp's Content Discovery and the site map
to identify patterns.

For JSON APIs, document the structure of every request and response body. Look for:
- Consistent field naming patterns (camelCase, snake_case, kebab-case)
- ID field formats (UUID, integer, base64)
- Timestamp formats
- Enum fields that accept a limited set of string values
- Nested objects that suggest related resources

mitmproxy with a custom addon can automate schema extraction from observed traffic:

```bash
mitmproxy --scripts extract_schema.py -p 8080
```

Build the schema incrementally as more endpoints and operations are discovered. The complete
picture emerges over multiple sessions covering different user roles and application states.

## Output

- OpenAPI, Swagger, or WSDL specification files.
- GraphQL schema file (from introspection or Clairvoyance).
- Postman or SoapUI collection generated from the schema.
- Schema reconstruction notes for undocumented APIs.
- List of operations, types, and fields of interest for targeted testing.

## Playbooks

- [REST API attack chain](../playbooks/rest-api.md)
- [GraphQL attack chain](../playbooks/graphql.md)
