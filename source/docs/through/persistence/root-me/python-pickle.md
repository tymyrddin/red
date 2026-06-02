# Python pickle

[root-me challenge: Python - pickle](https://www.root-me.org/en/Challenges/App-Script/Python-pickle): Authenticate as admin and capture the flag from `.passwd` file.

----

[HackTricks: Bypass pickle sandbox with the default installed python packages](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#bypass-pickle-sandbox-with-the-default-installed-python-packages)

## Counter moves

Pickle deserialises arbitrary objects, which means arbitrary code on untrusted data. A safe format, and never unpickling untrusted input, are the fixes. Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
