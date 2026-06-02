# Shellcode techniques

When writing shellcode for Linux, system calls (syscalls) are used. 

![Linux architecture](/_static/images/linux-architecture.png)

Best is to start with a basic shell, move onto egg hunters, reverse TCP shellcode, and finally, shellcode for 64-bit operating systems.

## Resources

* [Linux kernel map](https://makelinux.github.io/kernel/map/)

## Counter moves

Linux shellcode turns a memory bug into execution. The platform mitigations, NX, ASLR, and the stack protector, are what blunt the jump. Seen from the other side, this sits in the blue notes on [memory corruption and its limits](https://blue.tymyrddin.dev/docs/counter/memory/).
