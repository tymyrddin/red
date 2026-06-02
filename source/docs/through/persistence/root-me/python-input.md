# Python input()

[root-me challenge: Python - input()](https://www.root-me.org/en/Challenges/App-Script/Python-input): Get the password in the `.passwd` file by exploiting a vulnerability in the given python script.

----

`sys.stdout` is a built-in file object analogous to the interpreter's standard output stream in Python. `stdout` is used to display output directly to the screen console. Output can be of any form, even output from an expression statement such as `open(".passwd").readline()`.

## Counter moves

Treating input as code is the classic Python footgun. Parsing rather than evaluating input removes it. The defender's view is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
