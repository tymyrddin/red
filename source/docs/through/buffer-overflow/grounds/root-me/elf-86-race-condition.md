# ELF x86: Race condition

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Race-condition):

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
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
 
#define PASSWORD "/challenge/app-systeme/ch12/.passwd"
#define TMP_FILE "/tmp/tmp_file.txt"
 
int main(void)
{
  int fd_tmp, fd_rd;
  char ch;
 
 
  if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
    {
      printf("[-] Don't use a debugguer !\n");
      abort();
    }
  if((fd_tmp = open(TMP_FILE, O_WRONLY | O_CREAT, 0444)) == -1)
    {
      perror("[-] Can't create tmp file ");
      goto end;
    }
   
  if((fd_rd = open(PASSWORD, O_RDONLY)) == -1)
    {
      perror("[-] Can't open file ");
      goto end;
    }
   
  while(read(fd_rd, &ch, 1) == 1)
    {
      write(fd_tmp, &ch, 1);
    }
  close(fd_rd);
  close(fd_tmp);
  usleep(250000);
end:
  unlink(TMP_FILE);
   
  return 0;
}
```

## Resources

* [Secure Coding in C and C++ Race Conditions](https://repository.root-me.org/Programmation/C%20-%20C++/EN%20-%20Secure%20Coding%20in%20C%20and%20C++%20Race%20Conditions.pdf)
* [Race Condition Vulnerability Lab](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/EN%20-%20Race%20Condition%20Vulnerability%20Lab.pdf)
* [Exploiting Unix File-System Race Condition via Algorithmic Complexity Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Unix%20File-System%20Race%20Condition%20via%20Algorithmic%20Complexity%20Attacks.pdf)