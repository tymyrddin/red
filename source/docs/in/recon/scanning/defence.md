# Defence detection

* Check to see if a target is using a load balancing solution with the `lbd` (load balancing detector) command.
* To determine if the target is behind a web application firewall (WAF), use the `wafw00f` command.
* It may be needed to encode some attack tools to try to trick antivirus software into not seeing
the code as being harmful.
* To detect what ports a firewall is forwarding on to a target, use the `firewalk` command. Is also available for 
nmap as [firewalk.nse](https://nmap.org/nsedoc/scripts/firewalk.html) script.
