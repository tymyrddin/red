# Basic assembly shellcode

`thm.asm`: 

```text
global _start

section .text
_start:
    jmp MESSAGE      ; 1) let's jump to MESSAGE

GOBACK:
    mov rax, 0x1
    mov rdi, 0x1
    pop rsi          ; 3) we are popping into `rsi`; now we have the
                     ; address of "THM, Rocks!\r\n"
    mov rdx, 0xd
    syscall

    mov rax, 0x3c
    mov rdi, 0x0
    syscall

MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is, in this case, the address
                      ; of "THM, Rocks!\r\n", is pushed into the stack.
    db "THM, Rocks!", 0dh, 0ah
```

Compile and link to create an x64 Linux executable file:

    $ nasm -f elf64 thm.asm
    $ ls
    thm.asm  thm.o 
    $ ld thm.o -o thm
    $ ls             
    thm  thm.asm  thm.o
    ./thm            
    THM, Rocks!

Extract the shellcode by dumping the `.text` section of the compiled binary.

    $ objdump -d thm
    
    thm:     file format elf64-x86-64
    
    
    Disassembly of section .text:
    
    0000000000401000 <_start>:
      401000:	eb 1e                	jmp    401020 <MESSAGE>
    
    0000000000401002 <GOBACK>:
      401002:	b8 01 00 00 00       	mov    $0x1,%eax
      401007:	bf 01 00 00 00       	mov    $0x1,%edi
      40100c:	5e                   	pop    %rsi
      40100d:	ba 0d 00 00 00       	mov    $0xd,%edx
      401012:	0f 05                	syscall
      401014:	b8 3c 00 00 00       	mov    $0x3c,%eax
      401019:	bf 00 00 00 00       	mov    $0x0,%edi
      40101e:	0f 05                	syscall
    
    0000000000401020 <MESSAGE>:
      401020:	e8 dd ff ff ff       	call   401002 <GOBACK>
      401025:	54                   	push   %rsp
      401026:	48                   	rex.W
      401027:	4d 2c 20             	rex.WRB sub $0x20,%al
      40102a:	52                   	push   %rdx
      40102b:	6f                   	outsl  %ds:(%rsi),(%dx)
      40102c:	63 6b 73             	movsxd 0x73(%rbx),%ebp
      40102f:	21                   	.byte 0x21
      401030:	0d                   	.byte 0xd
      401031:	0a                   	.byte 0xa

Extract the hex value from the above output by dumping the `.text` section into a new file called `thm.text` in a 
binary format:
                                                                                
    $ objcopy -j .text -O binary thm thm.text
    $ ls
    thm  thm.asm  thm.o  thm.text

The `thm.text` file now contains the shellcode in binary format. To be able to use it, it needs to be converted to 
`hex` first. The `xxd` command has the `-i` option that will output the binary file in a C string directly:
                                                                                
    $ xxd -i thm.text
    unsigned char thm_text[] = {
      0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
      0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
      0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
      0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
      0x0d, 0x0a
    };
    unsigned int thm_text_len = 50;

To confirm that the extracted shellcode works as expected, execute the shellcode and inject it into a C program:

```text
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char message[] = {
        0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
        0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
        0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
        0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
        0x0d, 0x0a
    };
    
    (*(void(*)())message)();
    return 0;
}
```

Compile and execute:

    $ gcc -g -Wall -z execstack thm.c -o thmx
    $ ./thmx
    THM, Rocks!

## Resources

* [Linux System Call Table for x86 64](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
