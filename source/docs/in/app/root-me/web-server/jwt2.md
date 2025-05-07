# JWT (not) revoked token

[RootMe challege: JWT - Revoked token](https://www.root-me.org/en/Challenges/Web-Server/JWT-Revoked-token): 

Two endpoints are available :

    POST : /web-serveur/ch63/login
    GET : /web-serveur/ch63/admin

Gain access to the `admin` endpoint.

----

Developer blacklists full JWT or hash of the JWT, instead of revoking the JTI (JWT id).

![RootMe JWT jti](/_static/images/rootme-jwt2a.png)

Change request method to `POST`:

![RootMe JWT jti](/_static/images/rootme-jwt2b.png)

Get token for `admin:admin`:

![RootMe JWT jti](/_static/images/rootme-jwt2c.png)

Use the token to get the flag (add an `=` at the end of it).

