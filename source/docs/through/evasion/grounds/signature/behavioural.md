# Behavioural signatures

Obfuscating functions and properties can achieve a lot with minimal modification. Even after breaking static 
signatures attached to a file, modern engines may still observe the behaviour and functionality of the binary. 
This presents problems for attackers that cannot be solved with simple obfuscation.

Modern antivirus engines will employ two common methods to detect behaviour: observing imports and hooking known 
malicious calls. While imports can be easily obfuscated or modified with minimal requirements, hooking requires 
complex techniques.

## Lab

Obfuscate the following C snippet, ensuring no suspicious API calls are present in the IAT:

```text
    #include <windows.h>
    #include <stdio.h>
    #include <lm.h>
    
    int main() {
        printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
        CHAR hostName[260];
        DWORD hostNameLength = 260;
        if (GetComputerNameA(hostName, &hostNameLength)) {
            printf("hostname: %s\\n", hostName);
        }
    }
```

## Obfuscated code

1. Define the structure of the call
2. Obtain the handle of the module the call address is present in
3. Obtain the process address of the call

```text
    #include <windows.h>
    #include <stdio.h>
    #include <lm.h>
    
    // Define the structure of the call
    typedef BOOL (WINAPI* myNotGetComputerNameA)(
        LPSTR   lpBuffer,
        LPDWORD nSize
    );
    
    int main() {
    
        // Obtain the handle of the module the call address is present in 
        HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
        
        // Obtain the process address of the call
        myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, "GetComputerNameA");

        printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
        CHAR hostName[260];
        DWORD hostNameLength = 260;
        if (GetComputerNameA(hostName, &hostNameLength)) {
            printf("hostname: %s\\n", hostName);
        }
    }
```

Flag.

## Resources

* [The difference between signature-based and behavioural detections](https://s3cur3th1ssh1t.github.io/Signature_vs_Behaviour/)
* [The Journey of Evasion Enters Behavioural Phase](https://www.virusbulletin.com/virusbulletin/2016/07/journey-evasion-enters-behavioural-phase/)
