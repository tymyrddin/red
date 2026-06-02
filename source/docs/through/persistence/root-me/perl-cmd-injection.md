# Perl: Command injection

[root-me challenge: Perl - Command injection](https://www.root-me.org/en/Challenges/App-Script/Perl-Command-injection): Retrieve the password stored in `.passwd`.

----

```text
>>> |cat .passwd
```

## Resources

* [Security Issues in Perl Scripts](https://www.cgisecurity.com/lib/sips.html)
* [Perl](https://repository.root-me.org/Programmation/Perl/)

## Counter moves

Perl reaching a shell with tainted input is the bug. Taint mode and parameterised calls are the defence. The defensive counterpart is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
