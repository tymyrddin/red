# ELF MIPS basic crackme

[Root-me challenge](https://www.root-me.org/en/Challenges/Cracking/ELF-MIPS-Basic-Crackme): Find the validation password.

----

1. Decompile the binary in, for example, Ghidra.
2. Analysis

* There is no check on the length of the input
* There is a loop which checks that at indexes 8 - 16 there is an `i`

3. Check the stack.
4. Find the other characters.
5. The password is 19 characters long.

----

## Resources

* [Exploiting Buffer Overflows on MIPS Architectures - Lyon Yang](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Buffer%20Overflows%20on%20MIPS%20Architectures%20-%20Lyon%20Yang.pdf)
* [Reverse Engineering pour Débutants - Dennis Yurichev](https://repository.root-me.org/Reverse%20Engineering/FR%20-%20Reverse%20Engineering%20pour%20D%C3%A9butants%20-%20Dennis%20Yurichev.pdf)
* [Taming a Wild Nanomite-protected MIPS Binary With Symbolic Execution - Diary of a reverse-engineer](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20Taming%20a%20Wild%20Nanomite-protected%20MIPS%20Binary%20With%20Symbolic%20Execution%20-%20Diary%20of%20a%20reverse-engineer.pdf)
* [MIPS Green Sheet](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20MIPS%20Green%20Sheet.pdf)
* [MIPS Assembly Tutorial](https://repository.root-me.org/Reverse%20Engineering/MIPS/EN%20-%20MIPS%20Assembly%20Tutorial.pdf) 
