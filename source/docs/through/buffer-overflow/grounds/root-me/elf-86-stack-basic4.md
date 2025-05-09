# ELF x86: Stack buffer overflow basic 4

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-4): Can you return the env to me pleazzz? 

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
#include <dirent.h>
#include <string.h>
 
struct EnvInfo
{
  char home[128];
  char username[128];
  char shell[128];  
  char path[128];  
};
 
 
struct EnvInfo GetEnv(void)
{
  struct EnvInfo env;
  char *ptr;
   
  if((ptr = getenv("HOME")) == NULL)
    {
      printf("[-] Can't find HOME.\n");
      exit(0);
    }
  strcpy(env.home, ptr);
  if((ptr = getenv("USERNAME")) == NULL)
    {
      printf("[-] Can't find USERNAME.\n");
      exit(0);
    }
  strcpy(env.username, ptr);
  if((ptr = getenv("SHELL")) == NULL)
    {
      printf("[-] Can't find SHELL.\n");
      exit(0);
    }
  strcpy(env.shell, ptr);
  if((ptr = getenv("PATH")) == NULL)
    {
      printf("[-] Can't find PATH.\n");
      exit(0);
    }
  strcpy(env.path, ptr);
  return env;
}
 
int main(void)
{
  struct EnvInfo env;
   
  printf("[+] Getting env...\n");
  env = GetEnv();
   
  printf("HOME     = %s\n", env.home);
  printf("USERNAME = %s\n", env.username);
  printf("SHELL    = %s\n", env.shell);
  printf("PATH     = %s\n", env.path);
   
  return 0;  
}
```

----

```text
app-systeme-ch8@challenge02:~$ export PATH=$PATH:`python -c "print 'A'*160 + '\x31\xf9\xff\xbf' + '\x2b\xfb\xff\xbf'"`
app-systeme-ch8@challenge02:~$ ./ch8
[+] Getting env...
[-] Can't find USERNAME.
```

Need to think some more ...

## Resources

* [Débordement de tampon - dans la pile](https://www.root-me.org/spip.php?article807)
* [Buffer Overflow ou explication de "une faille de type bufferoverflow"](https://www.youtube.com/watch?v=u-OZQkv2ebw)
* [Exploitations avancees buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Exploitations%20avancees%20buffer%20overflow.pdf)
* [Stack Bug - Exploitation avancee de buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Stack%20Bug%20-%20Exploitation%20avancee%20de%20buffer%20overflow.pdf)
* [Runtime Attacks : Buffer OverFlow and Return Oriented Programming](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Runtime%20Attacks%20:%20Buffer%20OverFlow%20and%20Return%20Oriented%20Programming.pdf)
