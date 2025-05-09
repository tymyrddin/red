# ELF x86 basic

[RootMe challenge: ELF x86 - Basic](https://www.root-me.org/en/Challenges/Cracking/ELF-x86-Basic)

Find the validation password.

----

```text
┌──(kali㉿kali)-[~/Downloads/cracking/ch2]
└─$ ./ch2.bin
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################

username:     
Bad username
                                                                                                                                                                      
┌──(kali㉿kali)-[~/Downloads/cracking/ch2]
└─$ strings ch2.bin  | grep ^username -B 5 -A 2
john
the ripper
############################################################
##        Bienvennue dans ce challenge de cracking        ##
############################################################
username: 
password: 
987654321
```

## Resources

* [The GNU binary utils](https://repository.root-me.org/Administration/Unix/Linux/EN%20-%20The%20GNU%20binary%20utils.pdf)
* [Reverse Engineering pour Débutants - Dennis Yurichev](https://repository.root-me.org/Reverse%20Engineering/FR%20-%20Reverse%20Engineering%20pour%20D%C3%A9butants%20-%20Dennis%20Yurichev.pdf)
* [Executable and Linkable Format ELF](https://repository.root-me.org/Reverse%20Engineering/x86/Unix/EN%20-%20Executable%20and%20Linkable%20Format%20ELF.pdf)
* [Reverse Engineering for Beginners - Dennis Yurichev](https://repository.root-me.org/Reverse%20Engineering/EN%20-%20Reverse%20Engineering%20for%20Beginners%20-%20Dennis%20Yurichev.pdf)
