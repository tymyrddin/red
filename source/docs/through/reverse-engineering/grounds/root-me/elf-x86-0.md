# ELF x86 0 protection

[RootMe challenge: ELF x86 - 0 protection](https://www.root-me.org/en/Challenges/Cracking/ELF-x86-0-protection): First challenge of cracking, written in C with vi and compiled with GCC32.

----

```text
┌──(kali㉿kali)-[~/Downloads/cracking/ch1]
└─$ ./ch1.bin
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################

Veuillez entrer le mot de passe : 
Dommage, essaye encore une fois.
                                                                                                                                                                      
┌──(kali㉿kali)-[~/Downloads/cracking/ch1]
└─$ strings ch1.bin | grep passe -B 4
123456789
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################
Veuillez entrer le mot de passe : 
```

## Resources

* [The GNU binary utils](https://repository.root-me.org/Administration/Unix/Linux/EN%20-%20The%20GNU%20binary%20utils.pdf)
* [Reverse Engineering pour Débutants - Dennis Yurichev](https://repository.root-me.org/Reverse%20Engineering/FR%20-%20Reverse%20Engineering%20pour%20D%C3%A9butants%20-%20Dennis%20Yurichev.pdf)
* [Executable and Linkable Format ELF](https://repository.root-me.org/Reverse%20Engineering/x86/Unix/EN%20-%20Executable%20and%20Linkable%20Format%20ELF.pdf)
* [Reverse Engineering for Beginners - Dennis Yurichev](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20Reverse%20Engineering%20for%20Beginners%20-%20Dennis%20Yurichev.pdf)
