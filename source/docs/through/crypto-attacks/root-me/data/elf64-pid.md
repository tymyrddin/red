# ELF64 PID encryption

[RootMe: ELF64 - PID encryption](https://www.root-me.org/en/Challenges/Cryptanalysis/ELF64-PID-encryption): Bad idea to use predictable stuff.

## ELF

ELF (Executable and Linkable Format) is a standard file format for executable files, object code, shared libraries and core dumps. Linux and many UNIX-like operating systems use this format.

## Solution

Given: 

```text
/*
 * gcc ch21.c -lcrypt -o ch21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <sys/types.h>
#include <unistd.h>

int main (int argc, char *argv[]) {
    char pid[16];
    char *args[] = { "/bin/bash", "-p", 0 };

    snprintf(pid, sizeof(pid), "%i", getpid());
    if (argc != 2)
        return 0;

    printf("%s=%s",argv[1], crypt(pid, "$1$awesome"));

    if (strcmp(argv[1], crypt(pid, "$1$awesome")) == 0) {
        printf("WIN!\n");
        execve(args[0], &args[0], NULL);

    } else {
        printf("Fail... :/\n");
    }
    return 0;
}
```

We have to guess the PID though.

```text
# RootMe challenge ELF64 PID encryption
# https://red.tymyrddin.dev/projects/crypto/en/latest/docs/data/elf64-pid.html

import os
import crypt

PID = os.getpid() + 1
print(crypt.crypt(str(PID), "$1$awesome"))
```

```text
cryptanalyse-ch21@challenge01:~$ cd /tmp
cryptanalyse-ch21@challenge01:/tmp$ vi aha.py
cryptanalyse-ch21@challenge01:/tmp$ cd ~
cryptanalyse-ch21@challenge01:~$ ./ch21 $(python3 /tmp/aha.py)
$1$awesome$jAoZL2/ryRF9HRhYI9daW.=$1$awesome$5iuf4NVeErY8xYO/mxRC80Fail... :/
cryptanalyse-ch21@challenge01:~$ ./ch21 $(python3 /tmp/aha.py)
$1$awesome$O0AKFH9d5sNQf37g8ElUC0=$1$awesome$O0AKFH9d5sNQf37g8ElUC0WIN!
bash-5.0$ cat .passwd
```

Note: The `crypt` module is deprecated (see [PEP 594](https://peps.python.org/pep-0594/#crypt) for details and alternatives). Deprecated since version 3.11, will be removed in version 3.13. The [hashlib](https://docs.python.org/3/library/hashlib.html#module-hashlib) module is a potential replacement for certain use cases.
