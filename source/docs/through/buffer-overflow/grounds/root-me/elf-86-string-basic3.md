# ELF x86: Format string bug basic 3

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF32-Format-String-Bug-Basic-3): Another way to exploit a format string bug.

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
#include <unistd.h>
#include <string.h>
 
int main(int argc, char ** argv)
{
 
    // char    log_file = "/var/log/bin_error.log";
    char    outbuf[512];
    char    buffer[512];
    char    user[12];
 
    char *username = "root-me";
 
    // FILE *fp_log = fopen(log_file, "a");
 
    printf("Username: ");
    fgets(user, sizeof(user), stdin);
    user[strlen(user) - 1] = '\0';
 
    if (strcmp(user, username)) {
 
        sprintf (buffer, "ERR Wrong user: %400s", user);
        sprintf (outbuf, buffer);
        // fprintf (fp_log, "%s\n", outbuf);
   
        printf("Bad username: %s\n", user);
    }
   
    else {
 
        printf("Hello %s ! How are you ?\n", user);
    }
    // fclose(fp_log);
    return 0;
 
}
```

## Resources

* [Chaine de format - exploitation](https://www.root-me.org/spip.php?article798)
* [PHRACK - Advances in format string exploitation](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20PHRACK%20-%20Advances%20in%20format%20string%20exploitation.pdf)
* [DEFCON 18 Advanced Format String Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20DEFCON%2018%20Advanced%20Format%20String%20Attacks.pdf)
* [Format String and Double-Free Attacks](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Format%20String%20and%20Double-Free%20Attacks.pdf)
* [Les failles Format String](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Les%20failles%20Format%20String.pdf)
