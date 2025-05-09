# ELF x86: Stack buffer overflow basic 5

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-5): Please don’t smash me!

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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
 
#define BUFFER 512
 
struct Init
{
  char username[128];
  uid_t uid;
  pid_t pid;  
   
};
 
void cpstr(char *dst, const char *src)
{
  for(; *src; src++, dst++)
    {
      *dst = *src;
    }
  *dst = 0;
}

void chomp(char *buff)
{
  for(; *buff; buff++)
    {
      if(*buff == '\n' || *buff == '\r' || *buff == '\t')
        {
          *buff = 0;
          break;
        }
    }
}

struct Init Init(char *filename)
{
   
  FILE *file;
  struct Init init;
  char buff[BUFFER+1];  
   
   
  if((file = fopen(filename, "r")) == NULL)
    {
      perror("[-] fopen ");
      exit(0);
    }
   
  memset(&init, 0, sizeof(struct Init));
   
  init.pid = getpid();
  init.uid = getuid();
   
  while(fgets(buff, BUFFER, file) != NULL)
    {
      chomp(buff);
      if(strncmp(buff, "USERNAME=", 9) == 0)
        {
          cpstr(init.username, buff+9);
        }
    }
  fclose(file);
  return init;
}


int main(int argc, char **argv)
{
  struct Init init;
  if(argc != 2)
    {
      printf("Usage : %s <config_file>\n", argv[0]);
      exit(0);
    }
  init = Init(argv[1]);
  printf("[+] Runing the program with username %s, uid %d and pid %d.\n", init.username, init.uid, init.pid);
   
  return 0;
}
```

## Resources

* [Phrack 67 - Scraps of notes on remote stack overflow exploitation - pi3](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Phrack%2067%20-%20Scraps%20of%20notes%20on%20remote%20stack%20overflow%20exploitation%20-%20pi3.txt)
* [Stack Bug - Stack Overflow ASLR bypass using ret2reg](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Stack%20Bug%20-%20Stack%20Overflow%20ASLR%20bypass%20using%20ret2reg.pdf)
* [Stack Bug - Exploitation avancee de buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Stack%20Bug%20-%20Exploitation%20avancee%20de%20buffer%20overflow.pdf)
* [Stack Bug - Stack Overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Stack%20Bug%20-%20Stack%20Overflow.pdf)
* [Exploiting Stack Buffer Overflows in the Linux x86 Kernel](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Stack%20Buffer%20Overflows%20in%20the%20Linux%20x86%20Kernel.pdf)
