# Firmware and embedded reversing

Red team engagements increasingly include routers, IoT devices, and industrial control systems.
Firmware reversing involves stripped binaries, uncommon architectures, and minimal tooling
support compared to x86 PE or ELF work.

## Extracting firmware

Firmware images arrive in several ways: downloaded from a vendor update server, extracted from
a device via JTAG or UART, or dumped from flash storage directly.

`binwalk` is the standard first pass. It identifies file systems, compressed archives,
and embedded binaries within a firmware image:

```text
binwalk firmware.bin
```

To extract everything it recognises:

```text
binwalk -e firmware.bin
```

Common findings: SquashFS or JFFS2 file systems containing the root filesystem, uBoot
headers, kernel images, and configuration blobs. The extracted root filesystem often contains
the application binaries you want to analyse.

If `binwalk` does not identify structure, the image may be encrypted. Look for a decryption
stub in an earlier boot stage, or use entropy analysis to find regions of compressed or
encrypted content:

```text
binwalk -E firmware.bin
```

High uniform entropy across the entire image suggests encryption. Regions of lower entropy
followed by high entropy suggest a compressed or encrypted payload with a plaintext header.

## Identifying the architecture

Before loading into a disassembler, identify the target architecture:

```text
file rootfs/usr/sbin/httpd
readelf -h rootfs/usr/sbin/httpd
```

Common embedded architectures: MIPS (big and little endian), ARM (32-bit, various calling
conventions), PowerPC, and increasingly RISC-V for newer devices. The endianness matters;
getting it wrong produces nonsense disassembly.

`rabin2 -I` works for ELF binaries:

```text
rabin2 -I rootfs/usr/sbin/httpd
```

## Emulation with QEMU

Full-system emulation with QEMU lets you run the firmware or individual binaries without
the physical device. This enables dynamic analysis with Frida, GDB, or `strace`.

For a MIPS little-endian userspace binary:

```text
qemu-mipsel-static -L rootfs/ rootfs/usr/sbin/httpd
```

The `-L` flag sets the sysroot so that dynamic linker lookups resolve against the extracted
filesystem rather than the host.

For full-system emulation of a Linux-based router firmware, QEMU emulates the entire CPU
and peripherals. The setup depends on the specific board; `firmae` and `QEMU-based firmware
analysis` frameworks automate much of this for common devices.

## GDB for remote debugging

Attach GDB to a process running under QEMU user-mode emulation:

```text
qemu-mipsel-static -L rootfs/ -g 1234 rootfs/usr/sbin/httpd &
gdb-multiarch rootfs/usr/sbin/httpd
(gdb) target remote :1234
(gdb) set sysroot rootfs/
(gdb) b main
(gdb) c
```

`gdb-multiarch` supports cross-architecture debugging. Set the sysroot so that GDB can resolve
shared libraries from the firmware's filesystem.

## Ghidra for non-x86 targets

Ghidra supports MIPS, ARM, PowerPC, and most other embedded architectures through its
processor definitions. Load the binary and set the language to the correct architecture and
endianness.

For stripped firmware binaries with no symbol information, the function list will be empty
after initial auto-analysis. Start from known entry points: the reset vector, interrupt
handlers, and any function addresses embedded in configuration structures.

String references are often the most productive starting point. Look for error messages,
web server path strings, or configuration keys; these anchor analysis to specific functions
and provide context for naming.

## Practical targets

The typical red team objective in firmware reversing is one of:

Finding authentication bypasses: look for hardcoded credentials, default passwords embedded
in the binary, or authentication logic that can be bypassed by specific input patterns.

Finding command injection: web interfaces on embedded devices frequently pass user-supplied
input to shell commands. Follow `system()`, `popen()`, and `execve()` call sites; trace
parameters back to HTTP input handling.

Finding memory corruption: stack and heap overflows in network-facing services. `strings`
will often reveal format strings; `rabin2 -i` shows whether the binary has stack canaries
and NX enabled.

Ghidra's Vulnerable Functions script and community extensions for embedded targets surface
likely vulnerable call sites as a starting point.
