# Powershell: Command Injection

[root-me challenge: Powershell - Command Injection](https://www.root-me.org/en/Challenges/App-Script/Powershell-Command-Injection): Recover the database’s password.

----

```text
> ;cat .passwd
```

## Counter moves

Unsanitised input flowing into PowerShell execution is the opening. Input validation and constrained language mode are the counters. Defenders' notes on this are under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
