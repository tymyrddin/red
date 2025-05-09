# Stack operations and function-calling

***Function call***: When a function is called in assembly code, the calling program sets up the function call by first placing the function parameters on the stack in reverse order, the Extended Instruction Pointer (EIP) is saved on the stack so the program can continue where it left off when the function returns (return address), the call command is executed, and the address of the function is placed in the EIP to execute:

```text
0x5655621b <+38>:   mov     edx,DWORD PTR [eax]
0x5655621d <+40>:   mov     eax,DWORD PTR [ebx+0x4]
0x56556220 <+43>:   add     eax,0x4
0x56556223 <+46>:   mov     eax,DWORD PTR [eax]
0x56556225 <+48>:   sub     esp,0x8
0x56556228 <+51>:   push    edx
0x56556229 <+52>:   push    eac
0x5655622a <+53>:   call    0x565561a9 <greeting>
```

***Function prolog***: The called function's responsibilities are to save the calling program's EBP register on the stack, save the current ESP register to the EBP register (setting the current stack frame), and then to decrement the ESP register to make room for the function's local variables:

```text
0x000011a9 <+0>:    push    ebp
0x000011aa <+1>:    mov     ebp,esp
0x000011ac <+3>:    push    ebx
0x000011ad <+4>:    sub     esp,0x194
```

***Function epilog***: The last thing a called function does before returning to the calling program is to clean up the stack by incrementing ESP to EBP, clearing the stack as part of the leave statement. Then the saved EIP is popped off the stack as part of the return process:

```text
0x000011f3 <+74>:   leave
0x000011f4 <+75>:   ret
```
