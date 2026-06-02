# ELF x86 crackpass

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/ELF-x86-CrackPass): bypass the algorithm. Compiled with : `gcc -fno-stack-protector -o Crack && strip Crack` on Linux x86 (Debian)

----

1. NOP the `jne` at address `0x0804861e`
* Use `objdump -d 2 | grep 804861e`
* Replace `75` with `74` (from `jne` to `je`)

## Counter moves

The password check sits in plain view here. Server-side validation is what removes a local check entirely. Defenders' notes on this are under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
