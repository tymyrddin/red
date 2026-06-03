# PHP Register globals

[root-me challenge: PHP - Register globals](https://www.root-me.org/en/Challenges/Web-Server/PHP-register-globals): It seems that the developer often leaves backup files lying around ...

----

`register_globals`: In PHP < 4.1.1.1 or if misconfigured, `register_globals` may be active (or their behaviour is being mimicked). This implies that in global variables like `$_GET` if they have a value e.g. `$_GET["param"]="1234"`, it is accessible via `$param`. Sending HTTP parameters therefore overwrites variables used within the code.

```text
/index.php.bak
```

and:

```text
?_SESSION[logged]=1
```

## Techniques

- [Information disclosure](../../techniques/disclosure.md)
- [Surface discovery runbook](../../runbooks/recon.md)

## Counter moves

PHP Register globals is the variant in play. Server-side validation and least privilege are what these reduce to. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
