# TrickBot

1. Open Target Process ([OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess))
2. Allocate memory ([VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex))
3. Copy function into allocated memory ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory))
4. Copy shellcode into allocated memory ([WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory))
5. Flush cache to commit changes ([FlushInstructionCache](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache))
6. Create a remote thread ([CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread))
7. Resume the thread or fallback to create a new user thread ([ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread) or RtlCreateUserThread)

## Resources

Most recent first:

### Trickbot

* [VB2017: Turning Trickbot: decoding an encrypted command-and-control channel](https://www.virusbulletin.com/blog/2017/11/vb2017-video-turning-trickbot-decoding-encrypted-command-and-control-channel/)
* [Uperesia: How Trickbot tricks its victims](https://www.uperesia.com/how-trickbot-tricks-its-victims)
* [Flashpoint: With a boost from Necurs, Trickbot expands its targeting to numerous U.S. financial institutions](https://www.flashpoint-intel.com/blog/trickbot-targets-us-financials/)
* [MalwareBytes: Trick Bot – Dyreza’s successor](https://blog.malwarebytes.com/threat-analysis/2016/10/trick-bot-dyrezas-successor/)
* [Sentinel:How TrickBot Malware Hooking Engine Targets Windows 10 Browsers](https://www.sentinelone.com/labs/how-trickbot-malware-hooking-engine-targets-windows-10-browsers/)

### Dyre(za)

* [VB2015: Speaking Dyreza protocol. Advantages of 'learning' a new language](https://www.virusbulletin.com/virusbulletin/2016/12/vb2015-paper-speaking-dyreza-protocol-advantages-learning-new-language/)
* [Blueliv: Chasing cybercrime: network insights of Dyre and Dridex Trojan bankers](https://www.blueliv.com/research/chasing-the-cybercrime-network-insights-of-dyre-and-dridex-trojan-bankers-report/)
