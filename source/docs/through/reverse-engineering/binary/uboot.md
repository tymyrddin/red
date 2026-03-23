# uBoot and uImage format

U-Boot is the most widely deployed bootloader in embedded Linux devices: routers, access
points, set-top boxes, industrial gateways, and a large portion of the IoT landscape. When
you extract firmware from one of these devices, the first stage you encounter is usually
either a U-Boot image or a raw U-Boot binary. Understanding the format tells you what the
device loads, where it puts it, and how to extract the actual payload for analysis.

## The uImage container

A uImage is a U-Boot legacy image format. It wraps a payload (kernel, ramdisk, script, or
arbitrary binary) with a 64-byte header that describes the contents and tells U-Boot how
to handle them.

The header is defined in the U-Boot source as `image_header_t`:

```text
typedef struct image_header {
    uint32_t    ih_magic;    /* Image magic number       */
    uint32_t    ih_hcrc;     /* Image header CRC         */
    uint32_t    ih_time;     /* Image creation timestamp */
    uint32_t    ih_size;     /* Image data size          */
    uint32_t    ih_load;     /* Data load address        */
    uint32_t    ih_ep;       /* Entry point address      */
    uint32_t    ih_dcrc;     /* Image data CRC           */
    uint8_t     ih_os;       /* Operating system         */
    uint8_t     ih_arch;     /* CPU architecture         */
    uint8_t     ih_type;     /* Image type               */
    uint8_t     ih_comp;     /* Compression type         */
    uint8_t     ih_name[32]; /* Image name               */
} image_header_t;
```

The magic number is `0x27051956` (big-endian). This is the byte sequence to look for
when identifying a uImage in a larger firmware blob.

Key fields for analysis:

`ih_load`: the virtual address where U-Boot will copy the payload before execution. This
is the load address to use when setting up the disassembler.

`ih_ep`: the entry point, which may differ from the load address if the payload has an
offset entry.

`ih_arch`: identifies the CPU architecture. Common values: 2 = ARM, 5 = MIPS, 8 = MIPS64,
20 = ARM64.

`ih_comp`: compression. 0 = none, 1 = gzip, 2 = bzip2, 3 = lzma. The payload must be
decompressed before analysis.

`ih_type`: image type. 2 = kernel, 3 = ramdisk, 6 = multi, 7 = firmware.

## Reading the header

`binwalk` identifies uImage headers automatically:

```text
binwalk firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes,
                              header CRC: 0x1A2B3C4D,
                              created: 2023-04-11 09:12:33,
                              image size: 3145728 bytes,
                              data address: 0x80000000,
                              entry point: 0x80000000,
                              data CRC: 0x9E8F7D6C,
                              OS: Linux,
                              arch: MIPS,
                              image type: OS Kernel Image,
                              compression type: lzma,
                              image name: "OpenWrt Linux-5.15.0"
```

To read the header manually in Python:

```python
import struct

with open('firmware.bin', 'rb') as f:
    hdr = f.read(64)

magic, hcrc, timestamp, size, load, ep, dcrc = struct.unpack('>IIIIIII', hdr[:28])
os_id, arch, img_type, comp = struct.unpack('BBBB', hdr[28:32])
name = hdr[32:64].rstrip(b'\x00').decode('ascii', errors='replace')

print(f'Magic:      {hex(magic)}')
print(f'Load addr:  {hex(load)}')
print(f'Entry pt:   {hex(ep)}')
print(f'Arch:       {arch}')
print(f'Comp:       {comp}')
print(f'Name:       {name}')
```

All multi-byte fields in the uImage header are big-endian regardless of the payload
architecture.

## Extracting the payload

Strip the 64-byte header and decompress if necessary:

```text
dd if=firmware.bin of=payload.bin bs=64 skip=1
```

For a gzip-compressed payload:

```text
dd if=firmware.bin bs=64 skip=1 | gunzip > payload.bin
```

For lzma:

```text
dd if=firmware.bin bs=64 skip=1 | unlzma > payload.bin
```

`binwalk -e` handles this automatically and writes extracted payloads to a subdirectory:

```text
binwalk -e firmware.bin
```

Verify the extracted payload looks correct:

```text
file _firmware.bin.extracted/payload.bin
rabin2 -I _firmware.bin.extracted/payload.bin
```

If the payload is a Linux kernel, `file` reports `Linux kernel ARM boot executable zImage`
or similar. If it is a bare ELF, `rabin2` will parse it directly.

## FIT images

The Flattened Image Tree (FIT) is the modern U-Boot image format, replacing uImage in most
current devices. FIT images use a Devicetree Binary (DTB) structure to describe one or more
payloads with configuration nodes. The magic number is `0xD00DFEED`.

`binwalk` identifies FIT images:

```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Flattened device tree, size: 8388608 bytes,
                              version: 17
```

To parse a FIT image, `fdtdump` (from the dtc package) prints the full structure:

```text
fdtdump fit.img | head -100
```

The output shows each image node with its load address, entry point, and compression type,
equivalent to the uImage header fields but nested in a tree structure. Extract individual
payloads by reading the `data` property of each image node:

```python
import fdt  # pip install fdt

with open('fit.img', 'rb') as f:
    blob = f.read()

tree = fdt.parse_dtb(blob)

for node in tree.get_node('/images').nodes:
    name = node.name
    data = node.get_property('data').data
    load = node.get_property('load').data
    entry = node.get_property('entry').data
    print(f'{name}: load={hex(int.from_bytes(load, "big"))}, '
          f'entry={hex(int.from_bytes(entry, "big"))}, '
          f'size={len(data)}')
    with open(f'{name}.bin', 'wb') as out:
        out.write(bytes(data))
```

## U-Boot environment

The U-Boot environment block is a separate flash region containing key-value pairs that
control boot behaviour. It is not part of the uImage but is often present in a full flash
dump. The environment block starts with a 4-byte CRC, followed by newline-delimited
`key=value` pairs, padded with null bytes to the block size.

`strings` will reveal most of it directly:

```text
strings flash_dump.bin | grep -E "^[a-z]+=.*"
```

Of interest: `bootcmd` (the boot command executed on startup), `bootargs` (kernel command
line parameters, which may reveal the root filesystem type and location), and any hardcoded
IP addresses, credentials, or TFTP server addresses used for recovery or update.
