# Anatomy of binaries


## C compilation process

![C compilation process](/_static/images/compilation.png)

The preprocessing phase expands any `#define` and `#include` directives in the source file so that pure C code is ready to be compiled. To explicitly tell `gcc` to stop after preprocessing and show the intermediate output:

```text
nina@tardis:~/Development/anatomy$ gcc -E -P hello.c

typedef long unsigned int size_t;
typedef __builtin_va_list __gnuc_va_list;
typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
typedef signed char __int8_t;

...

extern int pclose (FILE *__stream);
extern FILE *popen (const char *__command, const char *__modes)
  __attribute__ ((__malloc__)) __attribute__ ((__malloc__ (pclose, 1))) ;
extern char *ctermid (char *__s) __attribute__ ((__nothrow__ , __leaf__))
  __attribute__ ((__access__ (__write_only__, 1)));
extern void flockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int ftrylockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void funlockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int __uflow (FILE *);
extern int __overflow (FILE *, int);

int
main(int argc, char *argv[]) {
 printf("%s", "Hello, world!\n");
 return 0;
}
```

The compilation phase takes the preprocessed code and translates it into assembly language, , in reasonably human-readable form, with symbolic information intact. Most compilers also perform heavy optimisation in his phase (configurable with switches such as options `-O0` through `-O3` in `gcc`. To tell `gcc` to stop after this
stage and store the assembly files to disk, use the `-S` flag. Pass the option
`-masm=intel` to gcc to have it produce assembly in Intel syntax instead of the default AT&T syntax:

```text
nina@tardis:~/Development/anatomy$ gcc -S -masm=intel hello.c
nina@tardis:~/Development/anatomy$ ls
hello.c  hello.s
nina@tardis:~/Development/anatomy$ cat hello.s
	.file	"hello.c"
	.intel_syntax noprefix
	.text
	.section	.rodata
.LC0:
	.string	"Hello, world!"
	.text
	.globl	main
	.type	main, @function
main:
.LFB0:
	.cfi_startproc
	endbr64
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	sub	rsp, 16
	mov	DWORD PTR -4[rbp], edi
	mov	QWORD PTR -16[rbp], rsi
	lea	rax, .LC0[rip]
	mov	rdi, rax
	call	puts@PLT
	mov	eax, 0
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
nina@tardis:~/Development/anatomy$ 
```

The input of the assembly phase is the set of assembly language files generated in the compilation phase, and the output is a set of object files (modules). Object files contain machine instructions executable by the processor. Typically, each source file corresponds to one assembly file, and each assembly file corresponds to one object file. To generate an object file, pass the `-c` flag to `gcc`:

```text
nina@tardis:~/Development/anatomy$ gcc -c hello.c
nina@tardis:~/Development/anatomy$ ls
hello.c  hello.o  hello.s
nina@tardis:~/Development/anatomy$ file hello.o
hello.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

The term `relocatable` in the file output indicates it is an object file and not an executable.

The linking phase links together all the object files into a single binary executable. The linking phase usually includes an additional optimisation pass, called link-time optimisation (LTO).

Static libraries (extension `.a` on Linux), are merged into the binary executable, allowing any references to them to be resolved entirely. Dynamic libraries, shared in memory among all programs that run on a system are loaded into memory only once, and any binary that wants to use the library needs to use the shared copy. to produce a complete binary executable, use `gcc` without switches:

```text
nina@tardis:~/Development/anatomy$ gcc hello.c
nina@tardis:~/Development/anatomy$ ls
a.out  hello.c  hello.o  hello.s
nina@tardis:~/Development/anatomy$ file a.out
a.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c8215b952047b1c7a485d388b97c85936de85da4, for GNU/Linux 3.2.0, not stripped
```

To override the default naming, pass the `-o` switch, followed by a name for the output file.

## Symbols and stripping

When compiling a program, compilers create and use symbols, which keep track of high-level functions and variables and record which binary code and data correspond to each symbol. To view the symbols in an `a.out` binary:

```text
nina@tardis:~/Development/anatomy$ readelf --syms a.out

Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (3)

Symbol table '.symtab' contains 36 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS Scrt1.o
     2: 000000000000038c    32 OBJECT  LOCAL  DEFAULT    4 __abi_tag
     3: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
     4: 0000000000001090     0 FUNC    LOCAL  DEFAULT   16 deregister_tm_clones
     5: 00000000000010c0     0 FUNC    LOCAL  DEFAULT   16 register_tm_clones
     6: 0000000000001100     0 FUNC    LOCAL  DEFAULT   16 __do_global_dtors_aux
     7: 0000000000004010     1 OBJECT  LOCAL  DEFAULT   26 completed.0
     8: 0000000000003dc0     0 OBJECT  LOCAL  DEFAULT   22 __do_global_dtor[...]
     9: 0000000000001140     0 FUNC    LOCAL  DEFAULT   16 frame_dummy
    10: 0000000000003db8     0 OBJECT  LOCAL  DEFAULT   21 __frame_dummy_in[...]
    11: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS hello.c
    12: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    13: 00000000000020f0     0 OBJECT  LOCAL  DEFAULT   20 __FRAME_END__
    14: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    15: 0000000000003dc8     0 OBJECT  LOCAL  DEFAULT   23 _DYNAMIC
    16: 0000000000002014     0 NOTYPE  LOCAL  DEFAULT   19 __GNU_EH_FRAME_HDR
    17: 0000000000003fb8     0 OBJECT  LOCAL  DEFAULT   24 _GLOBAL_OFFSET_TABLE_
    18: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    19: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    20: 0000000000004000     0 NOTYPE  WEAK   DEFAULT   25 data_start
    21: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
    22: 0000000000004010     0 NOTYPE  GLOBAL DEFAULT   25 _edata
    23: 0000000000001174     0 FUNC    GLOBAL HIDDEN    17 _fini
    24: 0000000000004000     0 NOTYPE  GLOBAL DEFAULT   25 __data_start
    25: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    26: 0000000000004008     0 OBJECT  GLOBAL HIDDEN    25 __dso_handle
    27: 0000000000002000     4 OBJECT  GLOBAL DEFAULT   18 _IO_stdin_used
    28: 0000000000004018     0 NOTYPE  GLOBAL DEFAULT   26 _end
    29: 0000000000001060    38 FUNC    GLOBAL DEFAULT   16 _start
    30: 0000000000004010     0 NOTYPE  GLOBAL DEFAULT   26 __bss_start
    31: 0000000000001149    41 FUNC    GLOBAL DEFAULT   16 main
    32: 0000000000004010     0 OBJECT  GLOBAL HIDDEN    25 __TMC_END__
    33: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    34: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@G[...]
    35: 0000000000001000     0 FUNC    GLOBAL HIDDEN    12 _init
```

Having a set of well-defined function symbols makes disassembly much easier because each function symbol can be used as a starting point for disassembly. Knowing which parts of a binary belong to which function, and what the function is called, also makes it much easier to compartmentalise and understand what the code is doing. Symbols can be parsed with `readelf`, or programmatically with a library like `libbfd`.

Stripping a binary removes the symbols which are not needed from a binary's symbol table. It makes the binary more difficult to disassemble, debug, and reverse engineer.

On a modern system with CPU speeds what they are, and memory/disk quantities what they are, stripping a binary will have very little practical impact on performance. It is mostly about debugging, "cleanliness", and personal preferences. Some developers prefer to always used stripped binaries for production, most leave the symbols in,  especially after experiencing a couple of frustrating situations not being able to pinpoint a problem, because the binaries were stripped.

The default behaviour of `gcc` is not to automatically strip newly compiled binaries. To strip:

```text
nina@tardis:~/Development/anatomy$ strip --strip-all a.out
nina@tardis:~/Development/anatomy$ file a.out
a.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c8215b952047b1c7a485d388b97c85936de85da4, for GNU/Linux 3.2.0, stripped
nina@tardis:~/Development/anatomy$ readelf --syms a.out

Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.34 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (3)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.2.5 (3)
```

Only a few symbols will be left in the symbol table, used to resolve dynamic dependencies when the binary is loaded into memory, but they are not much use when disassembling.

## Disassembling a binary

Disassembling an ***object file*** with `objdump`, showing the contents of the `.rodata` section:

```text
nina@tardis:~/Development/anatomy$ objdump -sj .rodata hello.o

hello.o:     file format elf64-x86-64

Contents of section .rodata:
 0000 48656c6c 6f2c2077 6f726c64 2100      Hello, world!.
```

To disassembles all the code in the object file in Intel syntax:

```text
nina@tardis:~/Development/anatomy$ objdump -M intel -d hello.o

hello.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	f3 0f 1e fa          	endbr64 
   4:	55                   	push   rbp
   5:	48 89 e5             	mov    rbp,rsp
   8:	48 83 ec 10          	sub    rsp,0x10
   c:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
   f:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
  13:	48 8d 05 00 00 00 00 	lea    rax,[rip+0x0]        # 1a <main+0x1a>
  1a:	48 89 c7             	mov    rdi,rax
  1d:	e8 00 00 00 00       	call   22 <main+0x22>
  22:	b8 00 00 00 00       	mov    eax,0x0
  27:	c9                   	leave  
  28:	c3                   	ret
```

To show all the relocation symbols present in the object file:

```text
nina@tardis:~/Development/anatomy$ readelf --relocs hello.o

Relocation section '.rela.text' at offset 0x1a8 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000016  000300000002 R_X86_64_PC32     0000000000000000 .rodata - 4
00000000001e  000500000004 R_X86_64_PLT32    0000000000000000 puts - 4

Relocation section '.rela.eh_frame' at offset 0x1d8 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000000020  000200000002 R_X86_64_PC32     0000000000000000 .text + 0
```

Disassembling ***an executable*** with `objdump`:

```text
nina@tardis:~/Development/anatomy$ objdump -M intel -d a.out

a.out:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    rsp,0x8
    1008:	48 8b 05 d9 2f 00 00 	mov    rax,QWORD PTR [rip+0x2fd9]        # 3fe8 <__gmon_start__@Base>
    100f:	48 85 c0             	test   rax,rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   rax
    1016:	48 83 c4 08          	add    rsp,0x8
    101a:	c3                   	ret    

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:	ff 35 9a 2f 00 00    	push   QWORD PTR [rip+0x2f9a]        # 3fc0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	f2 ff 25 9b 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f9b]        # 3fc8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102d:	0f 1f 00             	nop    DWORD PTR [rax]
    1030:	f3 0f 1e fa          	endbr64 
    1034:	68 00 00 00 00       	push   0x0
    1039:	f2 e9 e1 ff ff ff    	bnd jmp 1020 <_init+0x20>
    103f:	90                   	nop

Disassembly of section .plt.got:

0000000000001040 <__cxa_finalize@plt>:
    1040:	f3 0f 1e fa          	endbr64 
    1044:	f2 ff 25 ad 2f 00 00 	bnd jmp QWORD PTR [rip+0x2fad]        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    104b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .plt.sec:

0000000000001050 <puts@plt>:
    1050:	f3 0f 1e fa          	endbr64 
    1054:	f2 ff 25 75 2f 00 00 	bnd jmp QWORD PTR [rip+0x2f75]        # 3fd0 <puts@GLIBC_2.2.5>
    105b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000001060 <_start>:
    1060:	f3 0f 1e fa          	endbr64 
    1064:	31 ed                	xor    ebp,ebp
    1066:	49 89 d1             	mov    r9,rdx
    1069:	5e                   	pop    rsi
    106a:	48 89 e2             	mov    rdx,rsp
    106d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
    1071:	50                   	push   rax
    1072:	54                   	push   rsp
    1073:	45 31 c0             	xor    r8d,r8d
    1076:	31 c9                	xor    ecx,ecx
    1078:	48 8d 3d ca 00 00 00 	lea    rdi,[rip+0xca]        # 1149 <main>
    107f:	ff 15 53 2f 00 00    	call   QWORD PTR [rip+0x2f53]        # 3fd8 <__libc_start_main@GLIBC_2.34>
    1085:	f4                   	hlt    
    1086:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
    108d:	00 00 00 

0000000000001090 <deregister_tm_clones>:
    1090:	48 8d 3d 79 2f 00 00 	lea    rdi,[rip+0x2f79]        # 4010 <__TMC_END__>
    1097:	48 8d 05 72 2f 00 00 	lea    rax,[rip+0x2f72]        # 4010 <__TMC_END__>
    109e:	48 39 f8             	cmp    rax,rdi
    10a1:	74 15                	je     10b8 <deregister_tm_clones+0x28>
    10a3:	48 8b 05 36 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f36]        # 3fe0 <_ITM_deregisterTMCloneTable@Base>
    10aa:	48 85 c0             	test   rax,rax
    10ad:	74 09                	je     10b8 <deregister_tm_clones+0x28>
    10af:	ff e0                	jmp    rax
    10b1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
    10b8:	c3                   	ret    
    10b9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

00000000000010c0 <register_tm_clones>:
    10c0:	48 8d 3d 49 2f 00 00 	lea    rdi,[rip+0x2f49]        # 4010 <__TMC_END__>
    10c7:	48 8d 35 42 2f 00 00 	lea    rsi,[rip+0x2f42]        # 4010 <__TMC_END__>
    10ce:	48 29 fe             	sub    rsi,rdi
    10d1:	48 89 f0             	mov    rax,rsi
    10d4:	48 c1 ee 3f          	shr    rsi,0x3f
    10d8:	48 c1 f8 03          	sar    rax,0x3
    10dc:	48 01 c6             	add    rsi,rax
    10df:	48 d1 fe             	sar    rsi,1
    10e2:	74 14                	je     10f8 <register_tm_clones+0x38>
    10e4:	48 8b 05 05 2f 00 00 	mov    rax,QWORD PTR [rip+0x2f05]        # 3ff0 <_ITM_registerTMCloneTable@Base>
    10eb:	48 85 c0             	test   rax,rax
    10ee:	74 08                	je     10f8 <register_tm_clones+0x38>
    10f0:	ff e0                	jmp    rax
    10f2:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
    10f8:	c3                   	ret    
    10f9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001100 <__do_global_dtors_aux>:
    1100:	f3 0f 1e fa          	endbr64 
    1104:	80 3d 05 2f 00 00 00 	cmp    BYTE PTR [rip+0x2f05],0x0        # 4010 <__TMC_END__>
    110b:	75 2b                	jne    1138 <__do_global_dtors_aux+0x38>
    110d:	55                   	push   rbp
    110e:	48 83 3d e2 2e 00 00 	cmp    QWORD PTR [rip+0x2ee2],0x0        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>
    1115:	00 
    1116:	48 89 e5             	mov    rbp,rsp
    1119:	74 0c                	je     1127 <__do_global_dtors_aux+0x27>
    111b:	48 8b 3d e6 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2ee6]        # 4008 <__dso_handle>
    1122:	e8 19 ff ff ff       	call   1040 <__cxa_finalize@plt>
    1127:	e8 64 ff ff ff       	call   1090 <deregister_tm_clones>
    112c:	c6 05 dd 2e 00 00 01 	mov    BYTE PTR [rip+0x2edd],0x1        # 4010 <__TMC_END__>
    1133:	5d                   	pop    rbp
    1134:	c3                   	ret    
    1135:	0f 1f 00             	nop    DWORD PTR [rax]
    1138:	c3                   	ret    
    1139:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]

0000000000001140 <frame_dummy>:
    1140:	f3 0f 1e fa          	endbr64 
    1144:	e9 77 ff ff ff       	jmp    10c0 <register_tm_clones>

0000000000001149 <main>:
    1149:	f3 0f 1e fa          	endbr64 
    114d:	55                   	push   rbp
    114e:	48 89 e5             	mov    rbp,rsp
    1151:	48 83 ec 10          	sub    rsp,0x10
    1155:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
    1158:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    115c:	48 8d 05 a1 0e 00 00 	lea    rax,[rip+0xea1]        # 2004 <_IO_stdin_used+0x4>
    1163:	48 89 c7             	mov    rdi,rax
    1166:	e8 e5 fe ff ff       	call   1050 <puts@plt>
    116b:	b8 00 00 00 00       	mov    eax,0x0
    1170:	c9                   	leave  
    1171:	c3                   	ret    

Disassembly of section .fini:

0000000000001174 <_fini>:
    1174:	f3 0f 1e fa          	endbr64 
    1178:	48 83 ec 08          	sub    rsp,0x8
    117c:	48 83 c4 08          	add    rsp,0x8
    1180:	c3                   	ret    
nina@tardis:~/Development/anatomy$ 
```

The sections all contain code serving different functions, such as program initialisation or stubs for calling shared libraries.

## Loading and executing

A representation of a binary in memory does not necessarily correspond one-to-one with its on-disk representation. Large regions of zero-initialized data may be collapsed in the on-disk binary to save disk space, while all those zeros will be expanded in memory. Some parts of the on-disk binary may be ordered differently in memory or not loaded into memory at all. The details depend on the binary format.

### Running a binary

![Loading an ELF binary on a Linux-based system](/_static/images/loading-elf-simplified.png)

1. The OS starts by setting up a new process for the program to run in, including a virtual address
space. 
2. Then it maps an interpreter into the process's virtual memory. This is a user space program that knows how to load the binary and perform the necessary relocations. 
3. After loading the interpreter, the kernel transfers control to it, and the interpreter begins its work in user space.
4. The interpreter loads the binary into its virtual address space (the same space in which the interpreter is loaded). 
5. It then parses the binary to find out which dynamic libraries the binary uses. 
6. The interpreter maps these into the virtual address space. (and more)
7. The interpreter performs any necessary last-minute relocations in the binary's code sections to fill in the correct addresses for references to the dynamic libraries. In reality, the process of resolving references to functions in dynamic libraries is often deferred until later (lazy binding).)

### Interpreter

Linux ELF binaries come with a special section called `.interp` that specifies the path to the interpreter that is to be used to load the binary:

```text
nina@tardis:~/Development/anatomy$ readelf -p .interp a.out

String dump of section '.interp':
  [     0]  /lib64/ld-linux-x86-64.so.2
```

On Linux, the interpreter is most likely `ld-linux.so`. On Windows, the interpreter is part of `ntdll.dll`. 
