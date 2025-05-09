# PowerShell downgrade

The PowerShell downgrade attack is a very low-hanging fruit that allows attackers to modify the current PowerShell 
version to remove security features. Most PowerShell sessions will start with the most recent PowerShell engine, 
but attackers can manually change the version. By "downgrading" the PowerShell version to 2.0, security features 
that were not implemented until version 5.0 can be bypassed.

The attack only requires a one-liner. Launch a new PowerShell process with the flags `-Version` to specify the version.

    PowerShell -Version 2

This attack can actively be seen exploited in tools such as [Unicorn](https://github.com/trustedsec/unicorn).

    full_attack = '''powershell /w 1 /C "sv {0} -;sv {1} ec;sv {2} ((gv {3}).value.toString()+(gv {4}).value.toString());powershell (gv {5}).value.toString() (\\''''.format(ran1, ran2, ran3, ran1, ran2, ran3) + haha_av + ")" + '"'

Since this attack is extremely low-hanging fruit and simple, there are many ways for the blue team to detect and 
mitigate this attack. The two easiest mitigations are removing the PowerShell 2.0 engine from the device and denying 
access to PowerShell 2.0 via application blocklisting.
