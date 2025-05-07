# PHP Register globals

[root-me challenge: PHP - Register globals](https://www.root-me.org/en/Challenges/Web-Server/PHP-register-globals): It seems that the developer often leaves backup files lying around ...

----

`register_globals`: In PHP < 4.1.1.1 or if misconfigured, `register_globals` may be active (or their behaviour is being mimicked). This implies that in global variables like `$_GET` if they have a value e.g. `$_GET["param"]="1234"`, you can access it via `$param`. Therefore, by sending HTTP parameters you can overwrite variables that are used within the code.

```text
/index.php.bak
```

and:

```text
?_SESSION[logged]=1
```
