# Portable executable injection

PE Injection is generally favored over [DLL Injection](dll.md) by malware, because it does not require dropping any 
files to the disk.

When running in memory most, but not all, portable executables make use of 2 structures:

* Import Address Table (IAT), has all calls to `dll` functions point to a jump in the process’s jump table, allowing 
targets to easily be found and changed by the PE loader. 
* Base Relocation Table (Reloc), a table of pointers to every absolute address used in the code. During process 
initialisation, if the process is not being loaded at its base address, the PE loader will modify all the absolute 
addresses to work with the new base address.  

The Import Address Table and Reloc Table remain in memory once the process initialisation is finished, this makes for a very easy way to inject a process. With the ability to be loaded at any base address and use DLLs at any address, the process can simply get its current base address and image size from the PE header, and copy itself to any region of memory in almost any process. Here is the entire procedure broken down.

1. Get the current images base address and size (from the [PE header](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)).
2. Allocate enough memory for the image inside the processes own address space ([VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)).
3. Have the process copy its own image into the locally allocated memory (memcpy).
4. Allocate memory large enough to fit the image in the target process ([VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)).
5. Calculate the offset of the reloc table for the image that was copied into the local memory.
6. Iterate the reloc table of the local image and modify all absolute addresses to work at the address returned by VirtualAllocEx.
7. Copy the local image into the memory region allocated in the target process ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)).
8. Calculate the remote address of the function to be executed in the remote process by subtracting the address of the function in the current process by the base address of the current process, then adding it to the address of the allocated memory in the target process.
9. Create a new thread with the start address set to the remote address of the function ([CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)).

## Resources

* [MITRE: Portable executable injection](https://attack.mitre.org/techniques/T1055/002/)
* [A Comprehensive Guide To PE Structure, The Layman’s Way](https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/)
* [InfosecInstitute: Presenting the PE header](https://resources.infosecinstitute.com/topic/presenting-the-pe-header/)
