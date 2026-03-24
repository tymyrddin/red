# Bash: System 1

[root-me challenge: ELF32-System-1](https://www.root-me.org/en/Challenges/App-Script/ELF32-System-1?lang=en): Find your path, padawan! 

----

```text
Source

#include <stdlib.h>
#include <stdio.h>
 
/* gcc -m32 -o ch11 ch11.c */
 
int main(void) 
{
	system("ls /challenge/app-script/ch11/.passwd"); 
	return 0;
}
```

The `ls` command is not using an absolute path.

## Resources

* [Dangers of SUID Shell Scripts](https://repository.root-me.org/Administration/Unix/EN%20-%20Dangers%20of%20SUID%20Shell%20Scripts.pdf)
* [SUID Privileged Programs](https://repository.root-me.org/Administration/Unix/EN%20-%20SUID%20Privileged%20Programs.pdf)
