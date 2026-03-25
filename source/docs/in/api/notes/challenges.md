# Why APIs are hard to test

APIs have a larger and more complex attack surface than most testers expect. Understanding why
helps calibrate the effort required for a thorough assessment and explains why partial testing
consistently misses significant vulnerabilities.

## The surface is bigger than the documentation

Documented endpoints are the starting point, not the complete picture. Deprecated versions
remain live. Internal endpoints are reachable from the internet. Test automation, mobile clients,
and third-party integrations call endpoints that are never linked from the public documentation.
A test that only covers the documented surface will miss these.

## Use case propagation

Traditional UI testing checks whether the application produces the expected output for given
inputs. API testing is different because the API is the hub of logic for multiple consuming
applications, each with its own use case model. The number of meaningful input combinations
grows with each integration. Full coverage is not achievable; prioritisation based on impact is.

## Connected systems

APIs aggregate data from other APIs and backend systems. Testing one API in isolation does not
test the chain: a request that appears safe at the API layer may trigger unsafe behaviour in
a downstream service that trusts the API's input without further validation.

## Versioning

A well-managed API maintains multiple versions simultaneously. Each version may have different
security controls. Version 1 of an endpoint may lack input validation added in version 2.
Rate limits, authentication requirements, and authorisation checks added to a new version are
not automatically backported to old ones.

Testing the current, documented version and assuming older versions are equivalent is one of the
most common ways to miss significant vulnerabilities.

## Synchronous and asynchronous operations

A single API call can trigger multiple backend operations, some synchronous and some asynchronous.
The immediate response may succeed; a queued operation may process the input differently later.
Race conditions, time-of-check/time-of-use vulnerabilities, and delayed injection effects are
harder to detect than immediate responses.

## The shift from endpoint testing to system testing

Testing individual endpoints in isolation answers the wrong question. An endpoint that behaves
correctly on its own may participate in a workflow that produces unintended outcomes when used
at scale, out of sequence, or in combination with other legitimate calls. The vulnerabilities
that matter now live in the state machine, not the input validator.

Business logic flaws do not produce anomalous HTTP responses. The calls are authenticated,
authorised, and within documented parameter ranges. No scanner detects them. Finding them
requires understanding what the API is designed to do and then systematically attempting
outcomes the designer did not test: racing a balance check, skipping a workflow step, chaining
two legitimate operations to produce a third outcome neither was designed to enable.

The tester who only asks "does this endpoint behave correctly?" will miss most of the attack
surface. The useful question is: "what can someone achieve using this system over time, across
multiple sessions, in combinations the developer did not anticipate?"
