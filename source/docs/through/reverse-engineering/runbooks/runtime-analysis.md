# Runbook: runtime and memory analysis

Static analysis tells you what a binary contains. Runtime analysis tells you what it does.
For packed or encrypted samples, static analysis is often not enough: the real code only exists
in memory after the unpacker runs. This runbook covers extracting that material.

## Frida

Frida is a dynamic instrumentation toolkit that injects a JavaScript engine into a running process
and lets you intercept function calls, read and write memory, and trace execution without a
traditional debugger.

Install:

```text
pip install frida-tools
```

Attach to a running process by name or PID:

```text
frida Calculator
frida -p 1234
```

Or spawn a process under Frida's control from the start:

```text
frida -f target.exe --no-pause
```

### Intercepting API calls

The primary use is hooking imports to observe behaviour before the binary has a chance to detect
analysis. Hook `CreateFile` to log every file the binary touches:

```javascript
Interceptor.attach(Module.getExportByName('kernel32.dll', 'CreateFileW'), {
    onEnter: function(args) {
        console.log('CreateFileW: ' + args[0].readUtf16String());
    }
});
```

Hook `VirtualAlloc` to catch allocations that are likely to receive unpacked code:

```javascript
Interceptor.attach(Module.getExportByName('kernel32.dll', 'VirtualAlloc'), {
    onEnter: function(args) {
        this.size = args[1].toInt32();
        this.protect = args[3].toInt32();
    },
    onLeave: function(retval) {
        if (this.protect === 0x40) { // PAGE_EXECUTE_READWRITE
            console.log('RWX alloc of ' + this.size + ' bytes at ' + retval);
        }
    }
});
```

PAGE_EXECUTE_READWRITE allocations are a reliable indicator of an unpacker writing and then
executing code. Log the address, then dump the region after the packer has finished.

### Dumping memory regions

Once you have the address of a region containing unpacked or decrypted content, read it out:

```javascript
var addr = ptr('0x1A2B3C4D');
var size = 0x10000;
var data = Memory.readByteArray(addr, size);

// write to a file via the frida-compile / Python side
send(data);
```

On the Python side, receive and write to disk:

```python
import frida, sys

def on_message(message, data):
    if data:
        with open('dump.bin', 'wb') as f:
            f.write(data)

session = frida.attach('target.exe')
script = session.create_script(open('hook.js').read())
script.on('message', on_message)
script.load()
sys.stdin.read()
```

Analyse the dumped region as a standalone binary with `rabin2 -I dump.bin` to check whether
it is a valid PE or ELF. If it is, load it into Ghidra directly.

## Qiling

Qiling is a binary emulation framework that runs binaries in an instrumented environment
without requiring the target OS or hardware. It is useful when you cannot or do not want to
execute the sample on a live system.

Install:

```text
pip install qiling
```

Emulate a Windows PE on Linux:

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(['target.exe'], r'rootfs/x8664_windows', verbose=QL_VERBOSE.DEBUG)
ql.run()
```

`rootfs` is a directory tree containing the Windows DLLs Qiling needs. The project provides
pre-built rootfs images.

### Hooking in Qiling

Hook a Windows API to extract arguments:

```python
def hook_createfile(ql, address, params):
    print('CreateFile called with:', params['lpFileName'])

ql.os.set_api('CreateFileW', hook_createfile)
ql.run()
```

Hook an address to dump memory at a point after unpacking is complete:

```python
def dump_at(ql, address, data):
    mem = ql.mem.read(0x401000, 0x10000)
    with open('unpacked.bin', 'wb') as f:
        f.write(mem)

ql.hook_address(dump_at, 0x40150A)
ql.run()
```

## Extracting configs and C2 addresses

Decrypted configuration blocks typically contain C2 addresses, mutex names, campaign IDs, and
sleep intervals. They appear in memory after the unpacker runs, often shortly before the first
network call.

Hook `connect` or `WSAConnect` (Windows) to log C2 addresses at the point of connection:

```javascript
Interceptor.attach(Module.getExportByName('ws2_32.dll', 'connect'), {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = sockaddr.add(2).readU16be();
            var ip = sockaddr.add(4).readU32();
            console.log('connect: ' +
                ((ip & 0xff)) + '.' + ((ip >> 8) & 0xff) + '.' +
                ((ip >> 16) & 0xff) + '.' + ((ip >> 24) & 0xff) +
                ':' + port);
        }
    }
});
```

For configs stored in a structured block, once you have the base address from the VirtualAlloc
hook, scan for common indicators: null-terminated strings, IP address patterns, known magic
bytes used by specific malware families.

## Notes

Frida requires the target to run. If the binary detects a debugger or virtual environment,
address that before attaching. Common checks to patch: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`,
CPUID-based VM detection, timing checks using `GetTickCount` or `QueryPerformanceCounter`.

Qiling sidesteps most of these checks because it is not running the binary on real hardware.
The trade-off is that complex binaries with many API dependencies may fail to emulate correctly
without manual shim work.
