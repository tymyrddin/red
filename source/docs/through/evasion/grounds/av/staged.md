# Staged vs stageless payloads

* A stageless payload embeds the final shellcode directly into itself, like a packaged app that executes the shellcode 
in a single-step process. 
* Staged payloads work by using intermediary shellcodes that act as steps leading to the execution of a final shellcode. 
Each of these intermediary shellcodes is known as a stager, and its primary goal is to provide a means to retrieve 
the final shellcode and execute it eventually. There are payloads with several stages, but the usual case involves 
having a two-stage payload where the first stage, `stage0`, is a stub shellcode that will connect back to the 
attacker's machine to download the final shellcode to be executed. Once retrieved, the stage0 stub will inject the 
final shellcode somewhere in the memory of the payload's process and execute it.

Advantages of stageless payloads:

* The resulting executable packs all that is needed to get our shellcode working.
* The payload will execute without requiring additional network connections. The fewer the network interactions, the lesser your chances of being detected by an IPS.
* If you are attacking a host with very restricted network connectivity, you may want your whole payload to be in a single package.

Advantages of staged payloads:

* Small footprint on disk. Since stage0 is only in charge of downloading the final shellcode, it will most likely be small in size.
* The final shellcode isn't embedded into the executable. If your payload is captured, the Blue Team will only have access to the stage0 stub and nothing more.
* The final shellcode is loaded in memory and never touches the disk. This makes it less prone to be detected by AV solutions.
* You can reuse the same stage0 dropper for many shellcodes, as you can simply replace the final shellcode that gets served to the victim machine.