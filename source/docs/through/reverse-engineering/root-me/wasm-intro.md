# WASM introduction

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/WASM-Introduction): Do you know WebAssembly? Find the password that validates this crackme.

----

1. A Web assembly file is loaded: http://challenge01.root-me.org/cracking/ch41/index.wasm.
2. Decompile `index.wasm` with tools from the WebAssembly Binary Toolkit.
3. Analysis

* Look at `$check_password` code. Password is MD5 hashed.
* At the end of the file some constant values are defined.

4. Use, for example, the [hashes website](https://hashes.com/en/decrypt/hash) to decrypt.
5. Enter the decrypted password in the site to get the flag.

----

## Resources

* [wabt](https://github.com/WebAssembly/wabt/)
* [instructions.html](https://webassembly.github.io/spec/core/syntax/instructions.html)
