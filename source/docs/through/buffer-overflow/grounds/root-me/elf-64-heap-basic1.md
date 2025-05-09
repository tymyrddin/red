# ELF x64: Basic heap overflow

[RootMe challenge: ELF x64 - Basic heap overflow](https://www.root-me.org/en/Challenges/App-System/ELF-x64-Basic-heap-overflow): heap heap heap hooray 

Environment configuration:

```text
PIE         Position Independent Executable         Yes
RelRO       Read Only relocations 	            Yes
NX          Non-Executable Stack 	            Yes
Heap exec   Non-Executable Heap 	            Yes
ASLR        Address Space Layout Randomization 	    Yes
SF          Source Fortification 	            No
SSP         Stack-Smashing Protection 	            No
SRC         Source code access 	                    Yes
```

Source code:

```text
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
 
void    checkArg(const char *a)
{
  while (*a)
    {
      if (   (*a == ';')
          || (*a == '&')
          || (*a == '|')
          || (*a == ',')
          || (*a == '$')
          || (*a == '(')
          || (*a == ')')
          || (*a == '{')
          || (*a == '}')
          || (*a == '`')
          || (*a == '>')
          || (*a == '<') ) {
        puts("Forbidden !!!");
        exit(2);
      }
        a++;
    }
}
 
int     main()
{
  char  *arg = malloc(0x20);
  char  *cmd = malloc(0x400);
  setreuid(geteuid(), geteuid());
 
  strcpy(cmd, "/bin/ls -l ");
 
  printf("Enter directory you want to display : ");
 
  gets(arg);
  checkArg(arg);
 
  strcat(cmd, arg);
  system(cmd);
 
  return 0;
}
```
