# ELF x86 ptrace

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/ELF-x86-Ptrace): Compiled with GCC32 4.3.4 on linux gentoo.

----

1. Use, for example, Ghidra.
2. Search for `main()` in Functions.
3. Analysis (in Decompiler):

```text
(local_1e == local_14[4]) &&
(local_1d == local_14[5])) &&
(local_1c == local_14[1])) &&
(local_1b == local_14[10]))
puts("\nGood password !!!\n");
```

----

## Resources

* [The GNU binary utils](https://repository.root-me.org/Administration/Unix/Linux/EN%20-%20The%20GNU%20binary%20utils.pdf)
* [Ptrace - process trace](https://repository.root-me.org/Reverse%20Engineering/x86/Unix/EN%20-%20Ptrace%20-%20process%20trace.pdf)
* [SSTIC 06 - Playing with ptrace](https://repository.root-me.org/Reverse%20Engineering/x86/Unix/FR%20-%20SSTIC%2006%20-%20Playing%20with%20ptrace.pdf) 
