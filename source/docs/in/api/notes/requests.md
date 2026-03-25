# Building request collections

Understanding the format of API requests is prerequisite to testing them. The request format
comes from three sources: official documentation and specifications, observed traffic from using
the application as a normal user, and reverse engineering when neither of the first two is
complete.

## From documentation

OpenAPI and Swagger specifications import directly into Postman and generate a collection with
one request per operation. WSDL files for SOAP services import into SoapUI or Postman with full
operation definitions. GraphQL schemas (from introspection or Clairvoyance) import into InQL
for structured query generation.

Documentation describes the intended interface. The actual interface is often wider: undocumented
parameters are accepted, deprecated endpoints still respond, and internal operations appear in
traffic that are not listed in public documentation.

## From observed traffic

Routing all application traffic through a proxy builds a map of every API call the frontend
makes, including calls not described in the documentation. After a thorough walkthrough of the
application exercising every feature and every user role, the proxy site map is the most complete
picture of the actual API surface.

Export the proxy traffic as a Postman collection. Organise by resource type rather than by HTTP
method: all operations on a user resource together, all operations on an order resource together.
This makes it easier to test access control systematically.

## From reverse engineering

When there is no documentation and the application is not a web application (a mobile app or a
thick client), the API calls are discoverable by proxying the application's network traffic,
decompiling the application binary, or reading the JavaScript served to the browser.

## Runbooks

- [Endpoint discovery](../runbooks/endpoint-discovery.md)
- [Schema analysis](../runbooks/schema-analysis.md)
