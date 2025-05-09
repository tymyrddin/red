# PYC bytecode

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/PYC-ByteCode): A compiled crackme. Retrieve the password to validate this challenge.

----

1. Open in hex editor and use first 4 bits to identify the Python version.
2. Use `decompyle6` to decompile.
3. Python code with:

```text
K = KEY = 'I know, you love decrypting Byte Code !'
S = SOLUCE = [57, 73, 79, 16, 18, 26, 74, 50, 13, 38, 13, 79, 86, 86, 87]
I = (I + N) % len(KEY)
X = FLAG = ?
```

----

## Resources

* [Beyond python bytecode](https://repository.root-me.org/Programmation/Python/EN%20-%20Beyond%20python%20bytecode.pdf) 
