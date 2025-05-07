# Landslides

## Metasploit

For the best part of the last decades the undefeated champion of C2 frameworks was the [Metasploit](https://www.metasploit.com/) framework, but the default settings of the tool have been flagged by every Windows security product since 2007. For hacking Linux PC's it can still be a good choice.

It includes many community-contributed modules for attack, useful for most phases of penetration testing, including reconnaissance, vulnerability identification, exploitation, and command and control.

## Empire

[Empire](https://www.powershellempire.com/) and its later version [BC-security Empire](https://github.com/BC-SECURITY/Empire) is a PowerShell exploitation framework.

The Empire framework provides an exhaustive list of modules, exploits, and lateral movement techniques specifically designed for Active Directory. Many of the tools still work, and are still used in practice. These tools are very likely to be detected in advanced environments unless additional methods of concealment (using PowerPick or obfuscation techniques) are also used. The framework includes many PowerShell scripts and modules designed for gathering credentials (running Mimikatz), discovery and reconnaissance, privilege escalation, lateral movement, and persistence, etc.

Empire is no longer maintained by the original team, and BC Security, released version 3.0 in December 2019. The framework assumes that PowerShell allows attackers unhindered access to the environment. As of Windows 10, with PowerShell block logging and AMSI, this is no longer the case.

## Covenant

[Covenant](https://github.com/cobbr/Covenant) is a .NET C2 framework designed for collaboration during an attack operation.

## SilentTrinity

[SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) is a modern, asynchronous, multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR.
