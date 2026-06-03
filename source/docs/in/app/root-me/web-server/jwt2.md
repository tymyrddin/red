# JWT (not) revoked token

[RootMe challege: JWT - Revoked token](https://www.root-me.org/en/Challenges/Web-Server/JWT-Revoked-token): 

Two endpoints are available :

```text
POST : /web-serveur/ch63/login
GET : /web-serveur/ch63/admin
```

Gain access to the `admin` endpoint.

----

Developer blacklists full JWT or hash of the JWT, instead of revoking the JTI (JWT id).

![RootMe JWT jti](/_static/images/rootme-jwt2a.png)

Change request method to `POST`:

![RootMe JWT jti](/_static/images/rootme-jwt2b.png)

Get token for `admin:admin`:

![RootMe JWT jti](/_static/images/rootme-jwt2c.png)

Use the token to get the flag (add an `=` at the end of it).

## Techniques

- [JWT attacks](../../techniques/jwt.md)
- [JWT attacks runbook](../../runbooks/jwt.md)

## Counter moves

JWT (not) revoked token is the case here. Server-side validation and least privilege are what these reduce to. The defender's view can be found in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
