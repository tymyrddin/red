# ELF x64 golang basic

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/ELF-x64-Golang-basic): Find the validation password.

----

1. ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go `BuildID=2cf6d44559551c6185a598406fb67318d5b2396e`, with `debug_info`, not stripped
2. Analysis

* Golang calling convention uses the stack for parameters and return values.
* There is a `bytes.Compare` call between the `xored` flag and the key

3. Dump the `xored` flag
4. `rexor` it with the key

----

## Resources

* [Reversing Golang Binaries Like a Pro - RedNaga](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20Reversing%20Golang%20Binaries%20Like%20a%20Pro%20-%20RedNaga.pdf)
* [Golang Reverse - Zaytsev](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20Golang%20Reverse%20-%20Zaytsev.pdf) 
