# Websocket vulnerabilities

The websocket protocol is a protocol in the application layer of the OSI model, enabling full-duplex communication
between a client (browser) and a web server. This makes it possible to create dynamic, real-time web applications such
as instant messaging.

WebSockets are used for all kinds of purposes, including performing user actions and transmitting sensitive information.
Virtually any HTTP web security vulnerability can also exist in WebSockets communications.

## Steps

The two main tools for testing WebSockets are Burp Suite and OWASP ZAP. These tools allow for intercepting and modifying
WebSockets frames on the fly.

1. Check if there is indeed an authentication system and how it is implemented (access to functionalities without
   authentication).
2. Test access control in detail to try to obtain a privilege escalation.

## Cross-Site WebSocket Hijacking (CSWH)

A WebSocket communication is initiated through HTTP communication via the WebSocket handshake. The client tells the
server that it wants to initiate a WebSocket connection:

```text
GET /chat HTTP/1.1
Host: www.websocket.com:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Sec-WebSocket-Version: 13
Origin: http://www.websocket.com
Sec-WebSocket-Key: xxxxxxxxxxxxxxxxxxxxxxx
DNT: 1
Connection: keep-alive, Upgrade
Cookie: X-Authorization=yyyyyyyyyyyyyyyyyyyyyyyyyyyy
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket
```

The server accepts the connection with:

```text
HTTP/1.1 101 Switching Protocols
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Accept: zzzzzzzzzzzzzzzzzzzzzzzzzzzzz
```

The WebSocket protocol does not let a server authenticate the client during the handshake process. Only the normal
mechanisms for HTTP connections are available, including HTTP and TLS authentication and cookies. The upgraded handshake
still happens from HTTP to WebSocket. The HTTP sends the authentication information directly to WS. And this can be
exploited in Cross-Site WebSocket Hijacking (CSWH).

The Cross-Site WebSocket Hijacking attack is possible when the WebSocket handshake is vulnerable to [CSRF](csrf.md). The
communication channel between the two parties (client/server) is created according to the origin of the opening request.
If the protocol change request is only based on cookies, it is possible to lure a victim into initiating a request with
its session on the attacker’s server.

## Escalation

Once the Websocket communication is initiated, the client and the server communicate asynchronously. The format of the
exchanged data can be of any form. In practice, the most used WebSocket libraries use JSON format.

If a CSWH attack is successful, it becomes possible to communicate with the server via WebSockets without a victim’s
knowledge, to act in the place of a user, and also read the server messages sent via WebSockets.

## Variants

The cases are manipulating WebSocket messages to reach the usual injection sinks,
manipulating the handshake itself, and cross-site WebSocket hijacking where a handshake
authenticated by cookies alone can be initiated from an attacker's page. The
[client-side attacks runbook](../runbooks/client-side.md) covers the handshake and message
testing.

## Resources

* [Portswigger: Testing for WebSockets security vulnerabilities](https://portswigger.net/web-security/websockets)

## Counter moves

Websocket vulnerabilities is what this page works through. These come back to the same answers: validated input, encoded
output, server-side authorisation, and patched dependencies. Defenders' notes on this are
under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
