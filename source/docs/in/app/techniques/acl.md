# Broken access control

Access control determines whether an authenticated identity is permitted to perform a
specific action on a specific resource. Broken access control is consistently the most
frequently confirmed vulnerability in web application testing: it is invisible to scanners,
requires no payload, and is most effective when the tester understands how the application
is supposed to work.

The two failure modes are horizontal and vertical. Horizontal failures allow one user to
access another user's resources at the same privilege level. Vertical failures allow a
lower-privilege user to access functions or resources that should require higher privilege.
Both are common. Both are frequently exploitable using only a valid session token.

## How access control breaks

Access control is frequently enforced in the wrong place. UI-layer checks prevent the
application from presenting links or buttons for operations the current user should not
perform, but never prevented the underlying endpoint from responding. Any user who knows the
endpoint path and has a valid session can call it directly. Testing in the browser never
reveals this because the browser never shows the link; testing with a proxy always reveals
it because the endpoint responds.

Identifier-based access control is the most common horizontal failure. An application that
serves a user's data by fetching a record with an ID supplied in the request, without verifying
that the ID belongs to the requesting user, allows any user to access any record by
substituting IDs. The pattern is present in database keys, order numbers, document names,
message thread identifiers, and any other reference that appears in URLs, request bodies,
or response data.

Vertical access control failures often appear in multi-step workflows where the first step
checks the user's role and subsequent steps do not. An admin function that validates the
session's role at the page-load request but not at the form-submission request is exploitable
by a low-privilege user who submits the form directly.

HTTP method-based access control is another frequent failure. An endpoint that enforces
access control on `GET` but not on `POST`, or that checks for an admin role on `DELETE`
but not on `PUT`, is bypassed by changing the method. Some frameworks also honour `X-HTTP-Method-Override`
headers that allow a POST to impersonate a DELETE, bypassing controls applied at the routing
layer.

## Access control in modern applications

API-first applications separate access control concerns across multiple layers that are
maintained independently. The frontend enforces which actions are visible. The API gateway
may enforce authentication. Individual service endpoints enforce authorisation at the object
level. When these layers are maintained by different teams, gaps accumulate.

Authorisation logic embedded in the frontend JavaScript is particularly common in single-page
applications where the same codebase serves users at different privilege levels. A client-side
check that hides admin UI from non-admin users is the only control in the system if the
server's endpoints do not check separately.

Object-level authorisation in APIs (BOLA in the API-security framing) is the web application
equivalent of IDOR. The same fundamental failure — an identifier in the request is not
validated against the requesting user's permissions before the resource is returned — appears
in REST APIs, GraphQL resolvers, and WebSocket message handlers. The mechanics differ; the
cause is the same.

## Portswigger lab writeups

- [Unprotected admin functionality](../burp/acl/1.md)
- [Unprotected admin functionality with unpredictable URL](../burp/acl/2.md)
- [User role controlled by request parameter](../burp/acl/3.md)
- [User role can be modified in user profile](../burp/acl/4.md)
- [User ID controlled by request parameter](../burp/acl/5.md)
- [User ID controlled by request parameter, with unpredictable user IDs](../burp/acl/6.md)
- [User ID controlled by request parameter with data leakage in redirect](../burp/acl/7.md)
- [User ID controlled by request parameter with password disclosure](../burp/acl/8.md)
- [Insecure direct object references](../burp/acl/9.md)
- [URL-based access control can be circumvented](../burp/acl/10.md)
- [Method-based access control can be circumvented](../burp/acl/11.md)
- [Multistep process with no access control on one step](../burp/acl/12.md)
- [Referer-based access control](../burp/acl/13.md)

## Runbooks

- [Access control testing](../runbooks/access-control.md)
