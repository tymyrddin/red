# Bring your own vulnerable driver

BYOVD (Bring Your Own Vulnerable Driver) loads a legitimate, signed driver that
contains a known vulnerability. The attacker uses that vulnerability to execute code
at kernel level, typically to disable or blind the endpoint detection product that
would otherwise catch everything else.

It is signed, trusted software doing deeply untrustworthy things.

## Why it works

Windows requires kernel-mode code to be signed with a certificate trusted by Microsoft
(since Windows Vista x64 with mandatory driver signing). This protects against
unsigned malicious drivers being loaded directly.

But signed drivers with exploitable vulnerabilities already exist: game anti-cheat
drivers, hardware management tools, overclocking utilities. These were signed when
submitted to Microsoft's signing portal, but contain privileged operations exposed
to userland that an attacker can call to achieve arbitrary kernel memory reads and
writes.

Once kernel code execution is achieved:
- Kernel callbacks registered by EDR products can be removed
- Process hiding from the kernel process list becomes possible
- EDR's file system minifilter callbacks can be unregistered, blinding it to file
  operations
- Protected process flags can be cleared, allowing injection into otherwise
  tamper-protected processes

## The vulnerable driver ecosystem

The LOLDrivers project (loldrivers.io) catalogues known vulnerable and malicious
drivers with hash values, CVEs, and the capabilities they expose.

Commonly abused drivers:

`gdrv.sys` (Gigabyte): arbitrary kernel read/write via IOCTL interface. Used by
multiple ransomware groups and red teams. Hash values are now widely blocklisted.

`AsIO64.sys` (ASRock): IOCTL-based kernel read/write. Similar capability profile.

`RTCore64.sys` (Micro-Star): kernel read/write, used in the BYOVD attack against
Novell Client.

`procexp152.sys` (Sysinternals Process Explorer): driver legitimately used by Process
Explorer for process management, but exposes an IOCTL that terminates arbitrary
processes, including EDR processes.

The driver hash matters. EDR products maintain blocklists of known-vulnerable driver
hashes. Using a driver on the blocklist will trigger detection on load. Novel
vulnerable drivers (not yet catalogued) command high prices in the vulnerability market
for exactly this reason.

## Mechanism

The general flow:

1. Load the vulnerable driver using `sc.exe`, `NtLoadDriver`, or `CreateService`.
   This requires administrator privileges on modern Windows.
2. Open a handle to the driver's device object.
3. Send IOCTLs to the driver's vulnerable interface to achieve kernel read/write.
4. Use the kernel read/write primitive to locate and clear EDR callback registrations
   or modify protected process flags.

```text
# load a driver via sc.exe (requires admin)
sc create VulnDriver binpath= C:\path\to\driver.sys type= kernel start= demand
sc start VulnDriver

# open device handle and send IOCTLs via DeviceIoControl
# (implementation is driver-specific; see LOLDrivers entries)
```

## EDR callback removal

Windows EDR products register callbacks via kernel APIs to be notified of process
creation, thread creation, image loads, and registry operations:

- `PsSetCreateProcessNotifyRoutine` / `PsSetCreateProcessNotifyRoutineEx`
- `PsSetCreateThreadNotifyRoutine`
- `PsSetLoadImageNotifyRoutine`
- `CmRegisterCallback`

These callbacks are stored in kernel structures. With an arbitrary kernel write
primitive, the callback entries can be zeroed, removing the EDR's visibility into
these events.

The kernel structure layout changes between Windows versions; targeting a specific
version requires matching offsets. Public tools like EDRSandblast automate callback
enumeration and removal for common Windows versions.

## Limitations

BYOVD requires administrator privileges to load a driver. If the foothold is a
low-privilege user, privilege escalation must come first.

Driver blocklisting: Microsoft's Vulnerable Driver Blocklist (enforced via Windows
Defender Application Control and Hypervisor-Protected Code Integrity) blocks
loading of drivers with known-bad hashes. The list grows. Using a driver that is
not yet on the list requires either finding novel vulnerable drivers or using hashes
of older, unsigned versions.

Kernel version sensitivity: callback structure offsets are version-specific. A BYOVD
tool targeting Windows 10 21H2 may not work on Windows 11 22H2 without updated offsets.

Noise on load: driver load events (Event ID 7045 in System log, Sysmon Event ID 6)
are logged. Loading a driver from an unusual path or with an unusual service name
is a detectable action even if the driver itself is not yet on a blocklist.
