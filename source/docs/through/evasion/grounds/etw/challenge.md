# Challenge

In this scenario, you are a red team operator assigned to build an evasive script to disable ETW and execute a 
compiled binary. In this scenario, environment integrity is crucial, and the blue team is actively monitoring the 
environment. Your team has informed you that they are primarily concerned with monitoring web traffic; if halted, 
they will potentially alert your connection. The blue team is also assumed to be searching for suspicious logs; 
however, they are not forwarding logs. Create a script to execute a binary or command without interference.

1. PowerShell script block and module logging are enabled. => [Disable both GPO settings](takeover.md) from the cache for the PowerShell session.
2. Logs are not being forwarded => Delete any 4104 or 4103 logs that were generated. To remove the logs, simply use the Event Viewer GUI. PowerShell script block logs are located in `Microsoft/Windows/PowerShell/Operational` or `Microsoft-Windows-PowerShell`.
3. Run the binary `agent.exe` to get the flag.