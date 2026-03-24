# Modern memory corruption

Classic stack overflows with direct shellcode injection are mostly gone from serious
exploitation. What replaced them is a set of more complex primitives that work against
hardened targets.

## Heap exploitation

The heap is where dynamically allocated memory lives. Unlike the stack, its layout
is controlled by the allocator (ptmalloc2 on Linux, jemalloc in Firefox, PartitionAlloc
in Chrome), and exploitation techniques are allocator-specific.

Common heap corruption primitives:

Heap overflow: writing past the end of a heap allocation into an adjacent chunk's
metadata or content. The goal is to corrupt heap management structures (size fields,
forward/backward pointers) to redirect subsequent allocations or free operations.

Use-after-free (UAF): accessing memory through a pointer after the allocation has been
freed. If the freed memory is reclaimed by a different allocation of the same size,
the old pointer now points to attacker-controlled data. This is the dominant bug class
in browser exploitation.

Double-free: freeing an allocation twice corrupts the allocator's free list. In older
allocators this directly produced exploitable state; modern allocators have hardened
against it, but it remains a useful primitive in some contexts.

Type confusion: treating an object of one type as another. Common in languages with
complex type systems or when native code bridges across type boundaries (C extensions,
JIT compilers). Allows reading or writing fields at offsets that make no sense for the
actual object, producing arbitrary read/write primitives.

## Return-Oriented Programming

ROP was developed as a response to NX/DEP making the stack non-executable. Instead
of injecting shellcode, an attacker chains together short sequences of existing
executable code (gadgets) ending in a `ret` instruction. By controlling the stack,
they control which gadget executes next.

A typical ROP chain:

1. Find a stack overflow or similar write primitive to control the stack
2. Collect gadgets from the target binary and its libraries (ROPgadget, ropper, pwntools)
3. Build a chain that calls system functions directly or disables NX for a code region

```text
# find gadgets in a binary
ROPgadget --binary ./target --rop

# or with ropper
ropper -f ./target --search "pop rdi; ret"

# pwntools ROP class automates chain building
from pwn import *
elf = ELF('./target')
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
```

JOP (Jump-Oriented Programming) is a variant using `jmp` instead of `ret` as the
dispatch mechanism, designed to evade ROP-specific detection that monitors ret
instructions.

## ASLR bypass techniques

ASLR randomises load addresses, but several techniques defeat it:

Information leaks: any read primitive that exposes a pointer from a randomised region
reveals the base address. One leaked pointer breaks ASLR for that region. UAF bugs
frequently provide information leaks as well as write primitives.

Partial overwrites: on 32-bit systems, only 8 bits of the load address are randomised;
brute force is feasible. On 64-bit with 48-bit virtual address space, partial overwrites
of the low bytes of a pointer can redirect execution without needing the full address.

Heap spray: placing attacker-controlled content at many locations so that a guess at
a heap address has a reasonable probability of landing in controlled memory. Effective
before ASLR hardening; modern allocators and guard pages limit it.

## Browser exploit chains

Browser exploits are the canonical modern use of memory corruption. A typical chain:

1. JavaScript or WebAssembly triggers a UAF or type confusion bug in the renderer
2. The bug is developed into an arbitrary read/write primitive using object layout
   manipulation (heap grooming)
3. The read primitive leaks an address to defeat ASLR
4. The write primitive overwrites a function pointer or JIT code to redirect execution
5. A sandbox escape is required: the renderer runs in a low-privilege sandbox, so a
   second bug (often in the browser process or OS kernel) is needed for full compromise

Each step uses the output of the previous one. The total chain may involve two or
three separate CVEs.

## Kernel exploitation

Kernel bugs produce privilege escalation from a low-privilege process to root.
Common primitive classes:

- Kernel heap UAF (slab allocator)
- Race conditions in syscall handlers (TOCTOU)
- Integer overflows in size calculations producing heap underflows
- Out-of-bounds reads/writes in drivers

The goal is typically to overwrite a kernel structure to elevate the current process's
credentials, or to overwrite a function pointer in a kernel object to redirect
execution to a payload that does so.

```text
# check kernel mitigations on a target
cat /proc/sys/kernel/randomize_va_space      # ASLR: 2 = full
cat /sys/devices/system/cpu/vulnerabilities/ # Spectre/Meltdown mitigations
grep CONFIG_SMAP /boot/config-$(uname -r)    # SMAP status
grep CONFIG_SMEP /boot/config-$(uname -r)    # SMEP status
```

SMEP (Supervisor Mode Execution Prevention) stops the kernel from executing user-space
code. SMAP stops the kernel from reading or writing user-space memory directly. Both
require ROP chains or kernel-resident payloads rather than simple shellcode.
