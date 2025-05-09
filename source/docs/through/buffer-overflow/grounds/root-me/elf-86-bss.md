# ELF x86: BSS buffer overflow

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-BSS-buffer-overflow):

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
#include <stdlib.h>
 
char username[512] = {1};
void (*_atexit)(int) =  exit;
 
void cp_username(char *name, const char *arg)
{
  while((*(name++) = *(arg++)));
  *name = 0;
}
 
int main(int argc, char **argv)
{
  if(argc != 2)
    {
      printf("[-] Usage : %s <username>\n", argv[0]);
      exit(0);
    }
   
  cp_username(username, argv[1]);
  printf("[+] Running program with username : %s\n", username);
   
  _atexit(0);
  return 0;
}
```

## Resources

* [Heap and BSS overflow 1](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Heap%20and%20BSS%20overflow%201.pdf)
* [Heap and BSS overflow 2](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Heap%20and%20BSS%20overflow%202.pdf)
