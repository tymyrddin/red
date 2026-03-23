# Reverse engineering in Windows

This is a walkthrough of:

* Understanding Windows executables (PE format)
* Reversing a PE file
* Practical password extraction from a Windows binary

Windows programs communicate with the operating system through the Windows API. These APIs are organised around the file system (`CreateFile`, `ReadFile`), memory management (`VirtualAlloc`, `HeapAlloc`), the registry (`RegOpenKeyEx`), processes and threads (`CreateProcess`, `CreateThread`), and network communication (`WSAConnect`, `HttpSendRequest`). Recognising these imports in a binary quickly tells you what a program does before you look at a single instruction.

Install a text editor or IDE, and `mingw-w64` (for `gcc` on Windows) or MSVC from Visual Studio Build Tools. For analysis tools, `x64dbg`, `PE-bear`, `CFF Explorer`, and `strings` from Sysinternals are the primary toolkit.

Create a "hello world!" in C. Name it `hello.c`:

```text
#include <stdio.h>
void main(void)
{
printf ("hello world!\n");
}
```

## Compilation

Using MinGW `gcc` in a Windows terminal:

```text
C:\Dev\C> gcc -o hello.exe hello.c
```

The `hello.exe` file is the Windows executable. Confirm it runs:

```text
C:\Dev\C> hello.exe
hello world!
```

## Identification

The Windows `file` equivalent is built into PE analysis tools, but the Sysinternals `strings` utility and `dumpbin` (from MSVC) are the command-line starting point. With MinGW's `file` available:

```text
C:\Dev\C> file hello.exe
hello.exe: PE32+ executable (console) x86-64, for MS Windows
```

This confirms a 64-bit PE executable for the console subsystem. The `PE32+` designation means 64-bit; 32-bit binaries show `PE32`.

Extract readable strings with Sysinternals `strings`:

```text
C:\Dev\C> strings hello.exe
!This program cannot be run in DOS mode.
.text
.data
.rdata
.bss
.xdata
.pdata
hello world!
libmingw32.a(lib64_libmingw32_a-crt0_c.o)
mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
```

The `hello world!` string is visible, along with the MinGW runtime strings. The section names (`.text`, `.data`, `.rdata`) are the PE sections equivalent to ELF sections.

## dumpbin

`dumpbin` is part of the MSVC toolchain and provides detailed PE header and import information. To view PE headers:

```text
C:\Dev\C> dumpbin /headers hello.exe
Microsoft (R) COFF/PE Dumper Version 14.36.32537.0

Dump of file hello.exe

PE signature found

File Type: EXECUTABLE IMAGE

FILE HEADER VALUES
            8664 machine (x64)
               6 number of sections
        65A2F3E1 time date stamp
               0 file pointer to symbol table
               0 number of symbols
              F0 size of optional header
              22 characteristics
                   Executable
                   Application can handle large (>2GB) addresses

OPTIONAL HEADER VALUES
             20B magic # (PE32+)
           14.36 linker version
            1600 size of code
             A00 size of initialized data
               0 size of uninitialized data
            1870 entry point (0000000140001870)
            1000 base of code
       140000000 image base (0000000140000000 to 0000000140007FFF)
            1000 section alignment
             200 file alignment
            6.00 operating system version
            0.00 image version
            6.00 subsystem version
               0 Win32 version
            8000 size of image
             400 size of headers
               0 checksum
               3 subsystem (WINDOWS CUI)
```

The `subsystem (WINDOWS CUI)` confirms a console application. `subsystem (WINDOWS GUI)` would indicate a windowed application. The `image base` and `entry point` values are relevant when setting breakpoints.

To list imports:

```text
C:\Dev\C> dumpbin /imports hello.exe
Microsoft (R) COFF/PE Dumper Version 14.36.32537.0

Dump of file hello.exe

  Section contains the following imports:

    msvcrt.dll
              140005068 Import Address Table
              140006138 Import Name Table
                      0 time date stamp
                      0 Index of first forwarder reference

                  printf
                  __p___argc
                  __p___argv
                  __getmainargs
                  _cexit
                  _exit
                  _XcptFilter
                  exit
                  __set_app_type
                  _controlfp

    KERNEL32.dll
              140005000 Import Address Table
              1400060D0 Import Name Table
                      0 time date stamp
                      0 Index of first forwarder reference

                  ExitProcess
                  GetCommandLineA
                  VirtualProtect
                  LoadLibraryA
                  GetProcAddress
```

`KERNEL32.dll` and `msvcrt.dll` are the two fundamental imports for a simple C program. `KERNEL32.dll` provides process and memory management; `msvcrt.dll` is the C runtime. An unfamiliar binary importing `ws2_32.dll` (Winsock), `advapi32.dll` (registry, cryptography), or `wininet.dll` (HTTP) is doing something more interesting.

Moving to dynamic analysis, use `x64dbg` and optionally `API Monitor` or `Process Monitor`.

## x64dbg

`x64dbg` is the primary open-source debugger for Windows. Open `hello.exe` in x64dbg: it breaks at the entry point by default.

To set a breakpoint on `printf`, right-click the Symbols tab, locate `msvcrt.printf`, and press F2. Alternatively, at the command bar:

```text
bp msvcrt.printf
```

Run with F9. The debugger breaks before `printf` executes. The Registers panel shows the current state of all general-purpose registers. On x64 Windows, function arguments are passed in `RCX`, `RDX`, `R8`, `R9` (first four), then on the stack. At the `printf` breakpoint, `RCX` holds the address of the format string `"hello world!\n"`.

In the Dump panel, follow the address in `RCX` to confirm:

```text
00007FF6D6D41000  68 65 6C 6C 6F 20 77 6F  hello wo
00007FF6D6D41008  72 6C 64 21 0A 00 00 00  rld!....
```

To view the call stack at any point, use the Call Stack panel. Single-step with F7 (step into) or F8 (step over). After stepping over `printf`, the string has been printed and execution continues to the return.

To disassemble the main function in the CPU panel, right-click and select "Follow in Disassembler", or use Ctrl+G and enter `main` (if symbols are available) or the entry point address.

## PE-bear / CFF Explorer

For static PE inspection without a debugger, PE-bear and CFF Explorer provide a GUI over the raw PE structure. Open `hello.exe` in PE-bear:

- DOS Header: the `MZ` magic and stub. The `e_lfanew` field at offset `0x3C` points to the PE signature.
- NT Headers: `IMAGE_NT_HEADERS` containing the PE signature (`50 45 00 00`), File Header, and Optional Header.
- Section Headers: each section's virtual address, raw offset, size, and characteristics. `.text` has `0x60000020` characteristics (executable, readable, contains code). `.rdata` has `0x40000040` (readable, initialised data).
- Import Directory: lists every DLL and function the binary imports.
- Export Directory: populated only in DLLs.

CFF Explorer adds an Import Adder and Resource Editor, useful for reconstructing stripped imports in packed samples.

## Getting a password

Consider a Windows binary `passcode.exe` that prompts for a password and either accepts or rejects it.

### Static

Start with strings:

```text
C:\Dev\C\passcode> strings passcode.exe
!This program cannot be run in DOS mode.
Enter password:
Correct password!
Incorrect password!
msvcrt.dll
scanf
strlen
printf
puts
KERNEL32.dll
ExitProcess
```

The presence of `scanf`, `strlen`, `printf`, and `puts` alongside the three visible strings tells you the structure: prompt, read input, check length or value, print result. This is enough to form a hypothesis before touching the debugger.

Check imports with dumpbin:

```text
C:\Dev\C\passcode> dumpbin /imports passcode.exe

    msvcrt.dll
                  scanf
                  strlen
                  printf
                  puts
                  _cexit
```

No cryptography imports. No hashing. The comparison is almost certainly a plain arithmetic or string check in the binary itself.

Open in PE-bear to verify the entry point and note the `.text` section boundaries for scoping the disassembly search.

### Dynamic

Open `passcode.exe` in x64dbg. Let it run to the entry point. Search for string references to locate the password check: right-click in the CPU panel → "Search for" → "All referenced strings". The string `"Correct password!"` appears. Double-click it to jump to the instruction that references it.

The surrounding disassembly typically looks like this:

```text
0000000140001050 | sub rsp, 28                       | prologue
0000000140001054 | lea rcx, [passcode.140003000]     | "Enter password: "
000000014000105B | call <msvcrt.printf>              |
0000000140001060 | lea rdx, [rsp+30]                 | buffer
0000000140001064 | lea rcx, [passcode.140003010]     | "%s"
000000014000106B | call <msvcrt.scanf>               |
0000000140001070 | lea rcx, [rsp+30]                 | buffer
0000000140001074 | call <msvcrt.strlen>              |
0000000140001079 | cmp rax, 7                        | length check
000000014000107D | jne passcode.1400010A0            | → Incorrect
0000000140001083 | xor r8d, r8d                      | sum = 0
0000000140001086 | xor ecx, ecx                      | i = 0
0000000140001089 | movzx edx, byte [rsp+rcx+30]      | byte = buffer[i]
000000014000108E | add r8d, edx                      | sum += byte
0000000140001091 | inc rcx                           | i++
0000000140001094 | cmp rcx, 7                        | i < 7?
0000000140001098 | jl passcode.140001089             | loop
000000014000109A | cmp r8d, 2DE                      | sum == 734?
000000014000109E | jne passcode.1400010A0            | → Incorrect
00000001400010A0 | lea rcx, [passcode.140003020]     | "Correct password!"
```

The check is identical to the Linux version: length must be 7, sum of ASCII values must equal 734 (0x2DE). Set a breakpoint at the `cmp r8d, 2DE` instruction with F2. Run and enter any 7-character string. When the breakpoint hits, the Registers panel shows the computed sum in `R8D`.

To bypass the check without knowing the password, right-click the `jne` at `14000109E` and select "Patch" → "NOP" both bytes. With the jump removed, execution falls through to `"Correct password!"` regardless of input.

To extract the password instead, any 7-character string with ASCII values summing to 734 is valid. The string `hiiiiii` (104 + 105×6 = 734) works exactly as in the Linux version, because the algorithm is the same and the password space is identical.

Confirm with a run:

```text
C:\Dev\C\passcode> passcode.exe
Enter password: hiiiiii
Correct password!
```

## Resources

- [x64dbg](https://x64dbg.com/)
- [PE-bear](https://github.com/hasherezade/pe-bear)
- [CFF Explorer](https://ntcore.com/cff-explorer/)
- [Sysinternals strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
- [dumpbin reference](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference)
- [PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
