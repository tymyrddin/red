# ELF x86: Format string bug basic 2

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Format-string-bug-basic-2): Or how to write what you want where you want in the stack.

Environment configuration:

```text
PIE 	Position Independent Executable 	 No
RelRO 	Read Only relocations 	                 No
NX 	Non-Executable Stack 	                 YES
ASLR 	Address Space Layout Randomization 	 No
SF 	Source Fortification 	                 No
SSP 	Stack-Smashing Protection 	         No
SRC 	Source code access 	                 Yes
```

Source code:

```text
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
int main( int argc, char ** argv )
 
{
 
        int var;
        int check  = 0x04030201;
 
        char fmt[128];
 
        if (argc <2)
                exit(0);
 
        memset( fmt, 0, sizeof(fmt) );
 
        printf( "check at 0x%x\n", &check );
        printf( "argv[1] = [%s]\n", argv[1] );
 
        snprintf( fmt, sizeof(fmt), argv[1] );
 
        if ((check != 0x04030201) && (check != 0xdeadbeef))    
                printf ("\nYou are on the right way !\n");
 
        printf( "fmt=[%s]\n", fmt );
        printf( "check=0x%x\n", check );
 
        if (check==0xdeadbeef)
        {
                printf("Yeah dude ! You win !\n");
                setreuid(geteuid(), geteuid());
                system("/bin/bash");
        }
}
```

## Resources

* [Chaine de format - écriture en mémoire](https://www.root-me.org/spip.php?article799)
* [PHRACK - Advances in format string exploitation](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20PHRACK%20-%20Advances%20in%20format%20string%20exploitation.pdf)
* [DEFCON 18 Advanced Format String Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20DEFCON%2018%20Advanced%20Format%20String%20Attacks.pdf)
* [Format String and Double-Free Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Format%20String%20and%20Double-Free%20Attacks.pdf)
* [Les failles Format String](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Les%20failles%20Format%20String.pdf)
