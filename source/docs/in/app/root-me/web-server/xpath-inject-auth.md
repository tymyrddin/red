# XPath injection: authentication

[root-me challenge: XPath injection - Authentication](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication): retrieve the administrator password.

----

Using [Offensive Security Cheatsheet: XPath Injections](https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/xpath/):

```text
username=John' or '1'='1&password=
```

## Counter moves

XPath injection: authentication is what this page works through. Server-side validation and least privilege are what these reduce to. The defender's view is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
