# EDR evasion

Endpoint Detection and Response platforms are the primary security control on modern endpoints. They combine behavioural monitoring, telemetry collection, kernel-level visibility, and cloud-based analysis into a detection capability that is substantially more sophisticated than the signature-based antivirus it replaced. Evading EDR is no longer a matter of packing a binary differently; it requires understanding how the platform instruments the OS and operating in ways that avoid its detection logic.

## How EDR sees the endpoint

Most EDR products instrument the Windows kernel through a minifilter driver that intercepts file system operations, a network filter driver that captures socket activity, and userland hooks injected into each process that intercept API calls before they reach the kernel. This combination gives the platform visibility into what code runs, what it reads and writes, what network connections it makes, and how processes relate to each other.

The detection logic operates on this telemetry at multiple levels: static signatures on file content, behavioural rules on sequences of API calls, process tree anomalies, and cloud-based correlation across all endpoints in the tenant. A payload that evades one layer may still trigger another.

## Living off trusted processes (LOLBins)

The most durable evasion strategy is to avoid introducing new binaries at all. Windows ships with a large set of signed Microsoft binaries that can be abused to execute code, download content, and move laterally. These LOLBins (living-off-the-land binaries) carry Microsoft's signature and run in contexts that EDR platforms are cautious about blocking, because blocking them causes false positives in legitimate administrative operations.

Common examples: `mshta.exe` executes HTA applications and scripts; `certutil.exe` can download files and decode base64; `regsvr32.exe` can load COM objects from remote URLs via the scrobj.dll scriptlet mechanism; `wmic.exe` and its successor `winrm` execute commands on local and remote systems; `msiexec.exe` can install packages from URLs. The [LOLBAS project](https://lolbas-project.github.io/) catalogues the full set with exploitation details.

EDR vendors have responded by adding specific behavioural rules for the most-abused LOLBins. Detection rates for naive LOLBin abuse have risen significantly since 2020. The current approach is to combine LOLBins with indirect execution: rather than `mshta.exe` directly executing a payload, a chain of trusted binaries passes execution through multiple steps, making the process tree look like legitimate administrative activity.

## Userland hooking bypasses

When EDR injects a hook into a process, it does so by patching the first bytes of ntdll.dll functions to redirect execution to the EDR's monitoring code. Bypassing these hooks recovers the original kernel call without the monitoring intercept.

The standard approach is to load a fresh copy of ntdll.dll from disk (bypassing the in-memory patched version) and use the function addresses from the clean copy. Since ntdll.dll on disk is unpatched, the addresses point directly to the syscall instruction. This technique is described as "unhooking" and is implemented in several public tools including SysWhispers3 and Hell's Gate.

Direct syscalls take this further: rather than calling ntdll.dll at all, the attacker identifies the syscall number for the desired operation and executes the syscall instruction directly. This completely bypasses userland hooks, though kernel-level callbacks (PatchGuard-protected) remain active.

## Indirect execution and process injection

Code execution that originates from an unexpected process is an EDR signal. Code execution originating from a process that is expected to execute code, such as a JIT-compiling browser or an Office application running a macro, blends into the noise.

Process injection places shellcode into an already-running legitimate process. Classic techniques such as `VirtualAllocEx` and `WriteProcessMemory` followed by `CreateRemoteThread` are heavily monitored. Less monitored alternatives include APC injection (queueing execution via asynchronous procedure calls into a target thread), process hollowing (replacing a suspended process's image with the payload), and module stomping (overwriting a legitimate DLL loaded into a process with payload code, which makes the memory region appear backed by a legitimate file).

## Timing and behavioural blending

Modern EDR's behavioural detection looks for sequences of suspicious calls, not individual calls in isolation. Throttling execution, sleeping between operations, and mimicking the timing patterns of legitimate processes reduces the density of suspicious signals in the telemetry stream.

Operating during business hours, from processes and user contexts consistent with the user's normal behaviour, and against targets that the user would legitimately access, all contribute to activity that passes the EDR's baseline comparison. Detection at this level becomes a question of whether the behaviour feels wrong in context rather than whether it matches a known-bad pattern.
