# ELF x86: Format string bug basic 1

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Format-string-bug-basic-1): ... or how to read through the stack.

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

Source code:

```text
#include <stdio.h>
#include <unistd.h>
 
int main(int argc, char *argv[]){
        FILE *secret = fopen("/challenge/app-systeme/ch5/.passwd", "rt");
        char buffer[32];
        fgets(buffer, sizeof(buffer), secret);
        printf(argv[1]);
        fclose(secret);
        return 0;
}
```

## Resources

* [Chaine de format - lecture en mémoire](https://www.root-me.org/spip.php?article796)
* [Format Bugs - Exploiting format string](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Format%20Bugs%20-%20Exploiting%20format%20string.pdf)