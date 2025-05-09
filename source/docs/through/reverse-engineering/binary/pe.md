# Portable Executable (PE) format

PE is a modified version of the Common Object File Format (COFF), which was also used on Unix-based systems before being replaced by ELF. ???the 64-bit version of PE is called PE32+???

![32 bit PE](/_static/images/32-bit-pe.png)

The data structures shown in the figure are defined in `WinNT.h`, which is included in the Microsoft Windows Software Developer Kit.

## MS-DOS header

One of the main differences with ELF is the presence of an MS-DOS header, for backward compatibility. The main function of the MS-DOS header is to describe how to load and execute an MS-DOS stub, which comes right after the MS-DOS header. This stub is usually just a small MS-DOS program, which is run instead of the main program when the user executes a PE binary in MS-DOS.

The MS-DOS header starts with a magic value, which consists of the ASCII characters "MZ". An important field in the MS-DOS header is the last field, called `e_lfanew`, containing the file offset at which the real PE binary begins. Thus, when a PE-aware program loader opens the binary, it can read the MS-DOS header and then skip past it and the MS-DOS stub to go right to the start of the PE headers.

## PE Signature, File Header, and Optional Header

The PE headers is more or less analogous to ELF's executable header, except that it is split into three parts: a 32-
bit signature, a PE file header, and a PE optional header:

```text
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```


```text
nina@tardis:~/Development/pe$ objdump -x hello.exe

hello.exe:     file format pei-x86-64
hello.exe
architecture: i386:x86-64, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x0000000140001324

Characteristics 0x22
	executable
	large address aware

Time/Date		Thu Mar 30 14:27:09 2017
Magic			020b	(PE32+)
MajorLinkerVersion	14
MinorLinkerVersion	10
SizeOfCode		0000000000000e00
SizeOfInitializedData	0000000000001c00
SizeOfUninitializedData	0000000000000000
AddressOfEntryPoint	0000000000001324
BaseOfCode		0000000000001000
ImageBase		0000000140000000
SectionAlignment	00001000
FileAlignment		00000200
MajorOSystemVersion	6
MinorOSystemVersion	0
MajorImageVersion	0
MinorImageVersion	0
MajorSubsystemVersion	6
MinorSubsystemVersion	0
Win32Version		00000000
SizeOfImage		00007000
SizeOfHeaders		00000400
CheckSum		00000000
Subsystem		00000003	(Windows CUI)
DllCharacteristics	00008160
					HIGH_ENTROPY_VA
					DYNAMIC_BASE
					NX_COMPAT
					TERMINAL_SERVICE_AWARE
SizeOfStackReserve	0000000000100000
SizeOfStackCommit	0000000000001000
SizeOfHeapReserve	0000000000100000
SizeOfHeapCommit	0000000000001000
LoaderFlags		00000000
NumberOfRvaAndSizes	00000010

The Data Directory
Entry 0 0000000000000000 00000000 Export Directory [.edata (or where ever we found it)]
Entry 1 0000000000002724 000000a0 Import Directory [parts of .idata]
Entry 2 0000000000005000 000001e0 Resource Directory [.rsrc]
Entry 3 0000000000004000 00000168 Exception Directory [.pdata]
Entry 4 0000000000000000 00000000 Security Directory
Entry 5 0000000000006000 0000001c Base Relocation Directory [.reloc]
Entry 6 0000000000002220 00000070 Debug Directory
Entry 7 0000000000000000 00000000 Description Directory
Entry 8 0000000000000000 00000000 Special Directory
Entry 9 0000000000000000 00000000 Thread Storage Directory [.tls]
Entry a 0000000000002290 000000a0 Load Configuration Directory
Entry b 0000000000000000 00000000 Bound Import Directory
Entry c 0000000000002000 00000188 Import Address Table Directory
Entry d 0000000000000000 00000000 Delay Import Directory
Entry e 0000000000000000 00000000 CLR Runtime Header
Entry f 0000000000000000 00000000 Reserved
...
```

### PE Signature

The PE signature is a string containing the ASCII characters "PE", followed by two NULL characters. It is analogous to the magic bytes in the `e_ident` field in ELF's executable header.

### PE File Header

The `Machine` field describes the architecture of the machine for which the PE file is intended. The `NumberOfSections` field is the number of entries in the section header table, and `SizeOfOptionalHeader` is the size in bytes of the optional header that follows the file header. The `Characteristics` field contains flags describing things such as the endianness of the binary, whether it is a DLL, and whether it has been stripped.

### PE Optional Header

The PE optional header is ***not optional*** for executables (but it may be missing in object files). It contains lots of fields: a 16-bit magic value, which is set to `0x020b` for 64-bit PE files, several fields describing the major and minor version numbers of the linker that was used to create the binary, and the minimal operating system version needed to run the binary, to begin with. The `ImageBase` field describes the address at which to load the binary (PE binaries are designed to be loaded at a specific virtual address). Other pointer fields contain relative virtual addresses (RVAs), which are intended to be added to the base address to derive a virtual address.

## Section Header table

The PE section header table is an array of `IMAGE_SECTION_HEADER` structures, each of which describes a single section. Instead of referring to a string table as the ELF section headers do, PE section headers specify the section name using a simple character array field. Because the array is only 8 bytes long, PE section names are limited to 8 characters.

```text
//
// Section header format.
//

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

The PE format does not explicitly distinguish between sections and segments. The closest thing PE files have to ELF’s execution view is the `DataDirectory`, which provides the loader with a shortcut to certain portions of the binary needed for setting up the execution. But there is no separate program header table; the section header table is used for both linking and loading

## Sections

Many of the sections in PE files are directly comparable to ELF sections, often even having (almost) the same name.

```text
nina@tardis:~/Development/pe$ objdump -x hello.exe
...

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00000db8  0000000140001000  0000000140001000  00000400  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rdata        00000d72  0000000140002000  0000000140002000  00001200  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .data         00000200  0000000140003000  0000000140003000  00002000  2**4
                  CONTENTS, ALLOC, LOAD, DATA
  3 .pdata        00000168  0000000140004000  0000000140004000  00002200  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .rsrc         000001e0  0000000140005000  0000000140005000  00002400  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  5 .reloc        0000001c  0000000140006000  0000000140006000  00002600  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
```

### .edata and .idata

The most important PE sections that have no direct equivalent in ELF are `.edata` and `.idata`, which contain tables of exported and imported functions. The export directory and import directory entries in the `DataDirectory` array refer to these sections. The `.idata` section specifies which symbols (functions and data) the binary imports from shared libraries (DLLs in Windows terminology). The `.edata` section lists the symbols and their addresses that the binary exports. To resolve references to external symbols, the loader needs to match up the required imports with the export table of the DLL that provides the required symbols.

When these sections are not present (often the case), they are usually merged into `.rdata`, but their contents and workings remain the same.

When the loader resolves dependencies, it writes the resolved addresses into the Import Address Table (IAT). Similar to the Global Offset Table in ELF, the IAT is a table of resolved pointers with one slot per pointer. The IAT is also part of the `.idata` section, and it initially contains pointers to the names or identifying numbers of the symbols to be imported. The dynamic loader then replaces these pointers with pointers to the actual imported functions or variables. A call to a library function is then implemented as a call to a thunk for that function, which is nothing more than an indirect jump through the IAT slot for the function.

```text
140001ccf:	c3                   	ret    
   140001cd0:	ff 25 b2 03 00 00    	jmp    QWORD PTR [rip+0x3b2]        # 0x140002088
   140001cd6:	ff 25 a4 03 00 00    	jmp    QWORD PTR [rip+0x3a4]        # 0x140002080
   140001cdc:	ff 25 06 04 00 00    	jmp    QWORD PTR [rip+0x406]        # 0x1400020e8
   140001ce2:	ff 25 f8 03 00 00    	jmp    QWORD PTR [rip+0x3f8]        # 0x1400020e0
   140001ce8:	ff 25 ca 03 00 00    	jmp    QWORD PTR [rip+0x3ca]        # 0x1400020b8
   140001cee:	ff 25 54 04 00 00    	jmp    QWORD PTR [rip+0x454]        # 0x140002148
...
```

Thunks are often grouped together. The target addresses for the jumps are all stored in the import directory, contained in the `.rdata section` (starting at address `0x140002000`). These are jump slots in the IAT.

### Padding

When disassembling PE files, there are lots of `int3` instructions. Visual Studio makes these instructions as padding
(instead of the `nop` instructions used by `gcc`) to align functions and blocks of code in memory such that they can be accessed efficiently.2 The `int3` instruction is normally used by debuggers to set breakpoints; it causes the program to trap to the debugger or to crash if no debugger is present.
