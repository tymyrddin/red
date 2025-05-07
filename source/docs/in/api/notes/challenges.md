# Challenges

By relying on APIs, developers can design modular applications that leverage the expertise of other applications. They no longer need to create their own custom software to implement maps, payment processors, machine-learning algorithms, or authentication processes. As a result, popular! Many modern web applications have been quick to adopt APIs.

- APIs have exploded applications’ attack surfaces.
- They are often poorly defended providing a direct route to their data.
- Many APIs lack the security controls that other attack vectors have in place.

## Complexity

A few common rules of API testing:

* An API should provide expected output for a given input
* The inputs should appear within a particular range and values crossing the range must be rejected
* Any empty or null input must be rejected when it is unacceptable
* Incorrectly sized input must be rejected
* ...

API testing is simple. Its implementation is not. Complexity explodes, with consequences.

## Use case propagation

Traditional UI testing is limited to testing the functionality of the application. A tester compares the output of a test against expected outcomes. API testing uses a different approach. Being the central hub of logic and the gateway to data for (usually several) interfacing applications, the number of use cases in API testing is near-infinite. As a results, the number of required tests can rapidly exceed the possible workload of the people responsible for test case design.

## Access to connected systems

APIs pull data from multiple other APIs and back-end systems. The architecture looks like the roots of a tree, and it is impossible to have access to every environment in this system. 

Emulation and mocking of inaccessible resources is usually chosen to avoid testing bottlenecks. For API testing, this does not reduce the load. It just pushes it to another place. Plus, emulating race conditions for performance and load testing may not be such a good idea.

## Synchronous and asynchronous methods

One API can link several microservices and other APIs. A single call on an API can produce a load of serial and parallel activities. The complexities of an API can grow exponentially when it is combined with other API calls.

Testers then need to take the calling order of APIs into account in the test case design.

## API versioning

Versioning is another major cause of exploding the complexity in API testing. The API must identify missing values and allocate some default to allow an old version to work. It is entirely possible that some versions are called by some versions, but not by others.
