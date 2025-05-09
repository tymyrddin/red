# Dynamic-link library injection

The most common method of process injection is DLL Injection, which is popular due to how easy it is. A program can 
simply drop a DLL to the disk and then use "CreateRemoteThread" to call "LoadLibrary" in the target process, the 
loader will then take care of the rest. 

1. Locate a target process to inject ([CreateToolhelp32Snapshot()](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot), [Process32First()](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first), and [Process32Next()](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)).
2. Open the target process ([GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea), [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress), or [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)).
3. Allocate memory region for malicious DLL ([VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)).
4. Write the malicious DLL to allocated memory ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)).
5. Load and execute the malicious DLL ([LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) imported from kernel32. Once loaded, [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) can be used to execute memory using LoadLibrary as the starting function).

## Resources

* [MITRE: Dynamic-link library injection](https://attack.mitre.org/techniques/T1055/001/)
