# PowerShell reflection

Reflection allows a user or administrator to access and interact with .NET assemblies. From the Microsoft docs, 
_"Assemblies form the fundamental units of deployment, version control, reuse, activation scoping, and security 
permissions for .NET-based applications."_ 

`.NET` assemblies may seem foreign; however, we can make them more familiar by knowing they take shape in familiar 
formats such as `exe` and `dll`.

PowerShell reflection can be abused to modify and identify information from valuable DLLs. Matt Graeber published 
a one-liner to use Reflection to modify and bypass the AMSI utility:

    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

Broken down, all the reflection function and specify it wants to use an assembly from `[Ref.Assembly]` it will then 
obtain the type of the AMSI utility using `GetType`.

    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

The information collected from the previous section will be forwarded to the next function to obtain a specified field 
within the assembly using `GetField`.

    .GetField('amsiInitFailed','NonPublic,Static')

The assembly and field information will then be forwarded to the next parameter to set the value from `$false` to 
`$true` using `SetValue`.

    .SetValue($null,$true)

Once the `amsiInitFailed` field is set to `$true`, AMSI will respond with the response code: 
`AMSI_RESULT_NOT_DETECTED = 1`
