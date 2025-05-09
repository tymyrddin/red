# Bash: unquoted expression injection

[root-me challenge: Bash - unquoted expression injection](https://www.root-me.org/en/Challenges/App-Script/Bash-unquoted-expression-injection): Bypass this script’s security to recover the validation password.

----

`./somescript "0 -o foo"` makes any condition become

    test 1234 -eq 0 -o foo

This is the equivalent of `1234 == 0 || "foo"` in other languages, with one irrelevant comparison `OR`'d with the truth value of the string `foo`.

All non-empty strings are considered to be true, so this expression is always true.
