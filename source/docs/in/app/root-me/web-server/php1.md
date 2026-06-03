# PHP assert()

[root-me challenge: PHP - assert()](https://www.root-me.org/fr/Challenges/Web-Serveur/PHP-assert): Find and exploit the vulnerability to read the file `.passwd`.

![PHP assert()](/_static/images/rootme-php1.png)

etcetera.

```text
Remember to sanitise all user input! / Pensez à valider toutes les entrées utilisateurs !
Don't use assert! / N'utilisez pas assert 
```

## Resources

* [HackTricks: Code execution with Assert()](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#code-execution-with-assert)

## Techniques

- [Directory traversal](../../techniques/traversal.md)
- [Broken access control](../../techniques/acl.md)
- [Path traversal runbook](../../runbooks/traversal.md)

## Counter moves

PHP assert() is what this page works through. Server-side validation and least privilege are what these reduce to. The defender's view can be found in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
