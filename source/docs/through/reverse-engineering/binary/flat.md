# Flat and raw binary formats

A flat binary has no header, no section table, and no metadata. It is a sequence of bytes
intended to be loaded at a fixed address and executed from a known entry point. The loader,
whether a bootloader, a hardware reset vector, or a flashing tool, is responsible for placing
the code at the right address. Nothing in the file itself describes where it belongs.

Flat binaries are common in bare-metal microcontrollers (ARM Cortex-M, AVR, PIC, MSP430),
bootloader first stages, shellcode, and older embedded systems where a full operating system
is absent. Extracting firmware from a device via JTAG or reading flash directly often
produces a flat image.

## The challenge

Without a file header, the standard analysis workflow breaks immediately. `file` returns
`data`. `rabin2 -I` produces no useful output. The disassembler does not know the
architecture, the load address, or where execution begins.

You have to determine four things before analysis can start:

Architecture: what instruction set is the code written for?
Endianness: for architectures that have both variants (MIPS, ARM), which is this image?
Load address: at what virtual address does the binary expect to be placed in memory?
Entry point: where does execution begin?

## Determining the architecture

Hardware documentation is the most reliable source. If you know the device model, find the
datasheet or teardown notes that identify the CPU.

If you do not, look for instruction signatures in the binary. ARM Thumb-2 code begins with
characteristic 16-bit and 32-bit instruction patterns. MIPS has a recognisable NOP sled
pattern (`00 00 00 00`). x86 shellcode often starts with a short jump or a call/pop sequence.

`binwalk -A` runs an opcode scan against the image and reports which architectures it
recognises signatures for:

```text
binwalk -A firmware.bin
```

This is not definitive but narrows the candidates quickly. If two architectures both produce
hits, compare the hit density and the plausibility of the regions where hits cluster.

`cpu_rec` is a Python tool that applies statistical analysis to identify the instruction set:

```text
cpu_rec -f firmware.bin
```

It produces a probability-weighted list of candidate architectures based on byte distribution.

## Determining endianness

For ARM: if you see the byte sequence `00 00 A0 E3` near the start, that is a NOOP in
ARM little-endian (`mov r0, r0` in ARM encoding). The big-endian equivalent is `E3 A0 00 00`.

For MIPS: look for the reset vector area. MIPS big-endian images start at `0xBFC00000`;
the first instructions are typically a jump and a NOP. The encoding of `nop` is `00 00 00 00`
in both endiannesses, but the jump encoding differs and is recognisable.

`binwalk -A` reports the endianness alongside the architecture for most signatures.

## Determining the load address

The load address is where the binary expects to be placed in virtual memory. Getting this
wrong means that absolute addresses embedded in the code point to the wrong locations, and
the disassembler will show nonsensical branches and data references.

Sources for the load address:

Device datasheet: microcontrollers have a fixed flash base address specified in the memory
map. ARM Cortex-M devices typically execute from `0x00000000` or `0x08000000` depending on
boot configuration.

Bootloader output: serial console output during boot often logs the load address and
entry point of each stage.

Pointer analysis: if the binary contains a vector table (common on ARM Cortex-M), the
first word is the initial stack pointer and the second is the reset handler address. These
are absolute virtual addresses and constrain the load address.

For an ARM Cortex-M image, read the first eight bytes:

```python
import struct

with open('firmware.bin', 'rb') as f:
    data = f.read(8)

sp = struct.unpack('<I', data[0:4])[0]
reset = struct.unpack('<I', data[4:8])[0]

print(f'Initial SP: {hex(sp)}')
print(f'Reset handler: {hex(reset)}')
```

If the reset handler address is `0x08000009`, the binary is loaded at `0x08000000` (the low
bit is set because it is a Thumb address; subtract 1 to get the actual address).

## Loading in Ghidra

When importing a flat binary, Ghidra asks for the language and the base address. Set both
correctly before analysis runs, because re-importing is faster than trying to rebase after
the fact.

File > Import File, then in the import dialog select "Raw Binary" as the format. Choose the
correct language (for example `ARM:LE:32:Cortex` for a little-endian ARM Cortex binary) and
set the base address to the load address determined above.

After import, set the entry point manually before running auto-analysis:

```
Window > Script Manager > Run AddEntryPoint.py
```

Or place the cursor at the reset handler address and press `D` to disassemble, then `F` to
create a function. Run auto-analysis after at least one function exists.

## Loading in radare2

```text
r2 -a arm -b 32 -m 0x08000000 firmware.bin
```

`-a` sets the architecture, `-b` the bit width, `-m` the load address. For MIPS
big-endian:

```text
r2 -a mips -e cfg.bigendian=true -m 0xbfc00000 firmware.bin
```

After loading, run `aaa` for analysis. Use `s 0x08000000` to seek to the base, `pd 20`
to disassemble the first 20 instructions, and verify they look like plausible code for
the architecture.

## Finding the entry point in a stripped image

If the vector table approach does not apply, look for function prologues. ARM Thumb-2
functions typically begin with `PUSH {r4, lr}` or similar register saves. MIPS functions
begin with `addiu sp, sp, -N` to allocate stack space.

Entropy analysis helps too. The reset vector area and initialisation code tend to have
lower entropy than bulk data sections. Plot the entropy with `binwalk -E` and look for
structured regions at the start of the image.
