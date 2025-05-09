# ELF x86: Remote format string bug

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF32-Remote-Format-String-bug): See the power of format string!

Environment configuration:

```text
PIE 	        Position Independent Executable 	No 
RelRO 	        Read Only relocations 	                No 
NX 	        Non-Executable Stack 	                No 
Heap exec 	Non-Executable Heap 	                No 
ASLR 	        Address Space Layout Randomization 	No 
SF 	        Source Fortification 	                No 
SRC 	        Source code access 	                Yes 
```

Source code:

```text
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
 
#define LISTEN_PORT 56032
#define LENGTH 1024
 
/*
gcc -m32 -o ch32 ch32.c -z execstack
*/
 
extern char **environ;
int ssock;
 
 
 
int recv_loop(void)
{
 
  int csock;
  struct sockaddr_in caddr;
  socklen_t clen = sizeof(caddr);
  char input[LENGTH];
  char output[LENGTH];
 
   
  while(1)
  {
    if( (csock = accept(ssock, (struct sockaddr *) &caddr, &clen)) < 0) {
      perror("accept()");
      exit(1);
    }
    memset(input, '\0', LENGTH);
    memset(output, '\0', LENGTH);
   
    recv(csock, input, LENGTH-1, 0);
    snprintf (output, sizeof (output), input);
    output[sizeof (output) - 1] = '\0';
    send(csock, output, LENGTH-1, 0);
    close(csock);
  }
 
  return 0;
}
 
int main(void)
{
  int i, pid, yes = 1;
  struct sockaddr_in saddr;
 
  for(i=0; environ[i] != NULL; i++) {
    memset(environ[i], '\0', strlen(environ[i]));
  }
 
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  saddr.sin_port = htons(LISTEN_PORT);
 
  while(1)
  {
    pid = fork();
    if( pid == 0 ) {
      printf("run (pid=%d)\n", getpid());
      if( (ssock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        exit(1);
      }
     
      if(setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) <0) {
         perror("setsockopt()");
         exit(1);
      }
 
      if( bind(ssock, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
        perror("bind()");
        exit(1);
      }
 
      if( listen(ssock, 5) < 0) {
        perror("listen()");
        exit(1);
      }
                 
      recv_loop();
    } else {
       wait(NULL);
       close(ssock);
    }
  }
 
  return 0;
}
```

## Resources

* [Chaine de format - exploitation](https://www.root-me.org/spip.php?article798)
* [PHRACK - Advances in format string exploitation](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20PHRACK%20-%20Advances%20in%20format%20string%20exploitation.pdf)
* [DEFCON 18 Advanced Format String Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20DEFCON%2018%20Advanced%20Format%20String%20Attacks.pdf)
* [Format String and Double-Free Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Format%20String%20and%20Double-Free%20Attacks.pdf)
* [Les failles Format String](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Les%20failles%20Format%20String.pdf)

