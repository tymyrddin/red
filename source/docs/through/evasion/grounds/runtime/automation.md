# Automating, but ...

The previous methods are preferred.

## AMSI.fail

[amsi.fail](http://amsi.fail/) will compile and generate a PowerShell bypass from a collection of known bypasses. 
From amsi.fail, _"AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. The snippets are randomly selected from a small pool of techniques/variations before obfuscating. Every snippet is obfuscated at runtime/request so that no generated output share the same signatures."_

## AMSITrigger

[AMSITrigger](https://github.com/RythmStick/AMSITrigger) allows attackers to automatically identify strings that are 
flagging signatures to modify and break them. 
This method of bypassing AMSI is more consistent than others because it makes the file itself clean.

The syntax for using amsitrigger is relatively straightforward: specify the file or URL and what format to scan the 
file.

## Counter moves

Automating runtime bypasses scales them, but also makes them repeatable to detect. Behavioural detection on the bypass pattern is the counter. The defender's view is in the blue notes on [plausibility as cover](https://blue.tymyrddin.dev/docs/counter/evasion/).
