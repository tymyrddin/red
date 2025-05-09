# Shortcuts

Shortcuts or symbolic links are a technique used for referring to other files or applications within the OS. Once a 
user clicks on the shortcut file, the reference file or application is executed. Often, the Red team leverages this 
technique to gain initial access, privilege escalation, or persistence. The MITRE ATT&CK framework calls this 
"Shortcut modification" technique ([T1547](https://attack.mitre.org/techniques/T1547/009/)).

To use the shortcut modification technique, set the target section to execute files using:

* Rundll32
* Powershell
* Regsvr32
* Executable on disk