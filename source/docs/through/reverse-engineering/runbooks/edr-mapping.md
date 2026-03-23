# Runbook: EDR hook mapping

Understanding how an EDR instruments a process is a prerequisite for adversary simulation work
that needs to avoid or account for detection. This runbook covers enumerating hooks, identifying
collection points, and documenting blind spots.

The analysis tools (Frida, Python) run on Linux. The target is a Windows system running the EDR
you want to map. The workflow uses Frida's remote mode: `frida-server.exe` runs on the Windows
target, and the Frida client and scripts run on your Linux host.

## Set up remote access

Download the `frida-server` binary for Windows from the Frida releases page and transfer it to
the target. Run it with administrator privileges:

```text
frida-server.exe
```

By default it listens on `0.0.0.0:27042`. From your Linux host, set the target in your Frida
commands with `-H`:

```text
frida -H <target-ip>:27042 -e "Process.enumerateModules().forEach(m => console.log(m.name, m.base, m.size))"
```

In Python scripts, replace `frida.attach(...)` with `frida.get_remote_device().attach(...)`:

```python
import frida

device = frida.get_device_manager().add_remote_device('<target-ip>:27042')
session = device.attach('explorer.exe')
```

All subsequent Frida examples in this runbook follow this pattern.

## Enumerate loaded EDR components

List loaded modules for a target process to identify EDR DLLs:

```text
frida -H <target-ip>:27042 -p <pid> -e \
  "Process.enumerateModules().forEach(m => console.log(m.name, m.base, m.size))"
```

EDR user-mode components typically appear as DLLs injected into every process. Common naming
patterns: vendor name followed by `hook`, `monitor`, `agent`, `inject`, or similar. Note the
base addresses; you will need them when comparing against clean copies.

For kernel-mode drivers, you need a shell on the target. Over your C2 or SSH session:

```text
driverquery /fo list | findstr /i "edr av sensor"
sc query type= driver state= running
```

Minifilter drivers intercept file system operations; early-launch antimalware drivers run before
other drivers. Both are relevant for understanding what the EDR sees before user-mode code runs.

## Compare ntdll against a clean copy

The primary user-mode hooking surface is `ntdll.dll`. EDRs patch the first bytes of syscall
stubs to redirect execution through their monitoring code before the kernel transition happens.

Obtain a clean copy of `ntdll.dll` from a Windows system without the EDR, or extract it from
Windows installation media on your Linux host with `7z` or `cabextract`. Transfer it to your
Linux host for comparison.

The script below runs from your Linux host. It reads the on-disk ntdll from your local copy
and reads the in-memory version from the target via Frida remote:

```python
import pefile
import frida

disk_pe = pefile.PE('ntdll_clean.dll')
text_section = next(s for s in disk_pe.sections if b'.text' in s.Name)
disk_bytes = text_section.get_data()

device = frida.get_device_manager().add_remote_device('<target-ip>:27042')
session = device.attach('explorer.exe')

script = session.create_script("""
    var ntdll = Process.getModuleByName('ntdll.dll');
    var text = ntdll.base.add(0x1000);
    send(Memory.readByteArray(text, %d));
""" % len(disk_bytes))

mem_bytes = None

def on_message(msg, data):
    global mem_bytes
    if data:
        mem_bytes = data

script.on('message', on_message)
script.load()

import time
time.sleep(2)

diffs = [i for i in range(len(disk_bytes)) if disk_bytes[i] != mem_bytes[i]]
print(f'{len(diffs)} differing bytes')
for i in diffs[:20]:
    print(f'  offset {hex(i)}: disk={hex(disk_bytes[i])} mem={hex(mem_bytes[i])}')
```

Differences at the start of a function (typically the first 5 to 14 bytes) indicate an inline
hook. The patched bytes will usually contain a `jmp` to the EDR's monitoring code.

## Identify hook types

Three common patterns:

Inline hook: the first bytes of the target function are overwritten with a jump to a trampoline.
The original bytes are saved in a stub. Recognisable as `E9 xx xx xx xx` (relative near jump)
or `FF 25 xx xx xx xx` (indirect jump) at the start of the function.

Import Address Table hook: the IAT entry for a function is replaced with a pointer to the EDR's
version. The function itself is not modified. Detectable by comparing IAT entries against the
actual export addresses in the loaded DLL.

Hardware breakpoint hook: a debug register (DR0-DR3) is set to trigger on execution of a
specific address. No bytes are modified; the hook is entirely in CPU state. Detectable by
reading debug registers if you have sufficient privilege.

Document each hooked function with: function name, hook type, trampoline address, and the
EDR module the trampoline belongs to.

## Map telemetry collection points

Beyond hooks, identify what events the EDR collects from other sources. These commands run
on the Windows target via your shell session:

ETW (Event Tracing for Windows): many EDRs subscribe to ETW providers for process creation,
network events, and registry modification. Enumerate active ETW sessions:

```text
logman query -ets
```

Look for providers registered by the EDR vendor. The `Microsoft-Windows-Threat-Intelligence`
provider in particular is used by EDRs to receive kernel callbacks that are not accessible
from user mode.

Kernel callbacks: EDRs register for `PsSetCreateProcessNotifyRoutine`,
`PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine`. These fire in kernel
mode before user-mode code sees the event. There is no user-mode bypass for these; they
are relevant context for what the EDR will have seen when a process is created.

File system minifilters: the EDR's minifilter receives pre and post callbacks for file
operations. It will see file writes before they complete, which is how on-access scanning
works. The minifilter altitude determines the order relative to other filters.

## Document blind spots

Blind spots are conditions under which the EDR's instrumentation does not fire or is
insufficient to produce a detection.

Common categories:

Syscall bypass: calling NT syscalls directly without going through the hooked ntdll stubs.
The kernel receives the call; the EDR's user-mode hook does not. ETW-TI and kernel callbacks
still fire for most syscall categories, so this is not a complete bypass.

Early process injection: code executed before the EDR's DLL is loaded into a process will
not be covered by user-mode hooks in that process. Techniques that execute before the loader
runs or that target processes at a stage before injection completes fall into this category.

API gaps: functions that perform sensitive operations but are not hooked. The EDR vendor
makes choices about what to instrument based on performance and coverage trade-offs. Testing
against the hook list will reveal functions in scope; inferring what is out of scope requires
testing or documentation from the vendor.

For each blind spot, document: the condition, which hook types it bypasses, which telemetry
sources (ETW, kernel callbacks) remain active, and the net detection confidence.

This analysis feeds directly into adversary simulation planning: it identifies which techniques
are likely visible, which are likely invisible, and which fall into an uncertain middle ground
where telemetry exists but detection rules may not be written.
