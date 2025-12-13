# An adversary walks into a sandbox

Malware Analysis is the process of analysing a suspicious file to determine what it does on both a micro level 
(by looking at Assembly), and a macro level (by looking at what it does on the system). This process lets Blue 
Teamers gain a better understanding of malicious programs, which can aid them in developing detections.

There are two ways that a Blue Teamer can analyse a suspicious file

* One way is by Static Analysis, looking at the code on a micro-level (as previously stated) by using Disassemblers 
such as IDA or Ghidra.
* Another way is by Dynamic Analysis, observing what happens when a suspicious file is executed on the system. On 
the system, there are often many analysis tools installed, such as EDR Software, Sysmon, ProcMon, Process Hacker, 
and Debuggers (For example, OllyDebug, WinDbg, x64Dbg), and much more.

One of the most creative and effective ways that Blue Teamers have come up with to analyse suspicious-looking files 
is in the category of Dynamic Analysis. This method involves running the file in a containerised (or virtualised) 
environment, referred to as a Sandbox. Depending on the sandbox of choice, it can be customised for what version 
of Windows is running, the software installed on the machine, etc.

Sandboxes provide a safe and effective way to monitor what a suspicious-looking file does before running it on a 
production system (or allowing it to be sent to a production system). There are many commercial Sandboxes that may 
be in place in various parts of a network.

Each sandbox may work differently; for example, a Firewall may execute the attachment in the email and see what kind 
of network communications occur, whereas a Mail sandbox may open the email and see if an embedded file within the 
email triggers a download over a protocol like SMB in an attempt to steal a NetNTLM hash, where a host-based 
Anti-Virus Sandbox may execute the file and monitor for malicious programmatic behaviour or changes to the system.

There are various vendors that make various Sandbox products that Blue Teamers may be able to deploy in a 
corporate network (just a few examples):

* Palo Alto Wildfire (Firewall)
* Proofpoint TAP (Email Sandbox)
* Falcon Sandbox (EDR/Workstation)
* MimeCast (Email Sandbox)
* VirusTotal (Sample Submission Site)
* Any.Run (Sample Submission Site)
* Antiscan.me (Sample Submission Site)
* Joe Sandbox (Sample Submission Site)

