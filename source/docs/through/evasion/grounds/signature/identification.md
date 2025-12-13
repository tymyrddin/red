# Signature identification 

Identifying signatures, whether manually or automated, involves employing an iterative process to determine what 
byte a signature starts at. Recursively splitting a compiled binary in half and testing it, gives a rough estimate of a 
byte-range to investigate further.

Signature identification can be automated using scripts to split bytes over an interval. Find-AVSignature
will split a provided range of bytes through a given interval. This script relieves a lot of the manual work, but 
still has several limitations. It still requires an appropriate interval to be set to function properly and will 
also only observe strings of the binary when dropped to disk rather than scanning using the full functionality of 
the antivirus engine. 

Alternatives are other FOSS tools that leverage the engines themselves to scan the file, including DefenderCheck, 
[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), and [AMSITrigger](https://github.com/RythmStick/AMSITrigger).

## ThreatCheck

ThreatCheck is a fork of DefenderCheck and is the most widely used of the three. To identify possible signatures, 
ThreatCheck leverages several antivirus engines against split compiled binaries and reports where it believes bad 
bytes are present. ThreatCheck does not provide a pre-compiled release.

    C:\>ThreatCheck.exe --help
      -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
      -f, --file      analyse a file on disk
      -u, --url       analyse a file from a URL
      --help          Display this help screen.
      --version       Display version information.

## AMSITrigger

AMSI leverages the runtime, making signatures harder to identify and resolve, and supports some file types
which ThreatCheck does not, like Powershell. AMSITrigger will scan functions against a provided PowerShell script 
and report any specific sections of code it believes need to be alerted on. AMSITrigger provides a pre-compiled 
release on GitHub.

    C:\>amsitrigger.exe --help
        -i, --inputfile=VALUE       Powershell filename
        -u, --url=VALUE             URL eg. <https://10.1.1.1/Invoke-NinjaCopy.ps1>
        -f, --format=VALUE          Output Format:
                                      1 - Only show Triggers
                                      2 - Show Triggers with Line numbers
                                      3 - Show Triggers inline with code
                                      4 - Show AMSI calls (xmas tree mode)
        -d, --debug                 Show Debug Info
        -m, --maxsiglength=VALUE    Maximum signature Length to cater for,
                                      default=2048
        -c, --chunksize=VALUE       Chunk size to send to AMSIScanBuffer,
                                      default=4096
        -h, -?, --help              Show Help

## Lab

`-e Defender` gave errors. `-e AMSI` worked, and gave answers to Task 3 and Task 2 (rounding 50500 to 51000).

```text
C:\Users\Student\Desktop\Tools>.\ThreatCheck.exe -f C:\Users\Student\Desktop\Binaries\shell.exe -e AMSI
[+] Target file size: 73802 bytes
[+] Analysing...
[*] Testing 36901 bytes
[*] No threat found, increasing size
...
[*] Testing 50503 bytes
[*] Threat found, splitting
[*] Testing 50500 bytes
[*] Threat found, splitting
[!] Identified end of bad bytes at offset 0xC544
00000000   95 CE 77 FF D5 90 E9 09  00 00 00 3C 7E 5F 66 24   ?IwÿO?é····<~_f$
00000010   8C 09 80 09 31 C0 E9 09  00 00 00 14 4A C5 E1 9B   ?·?·1Aé·····JÅá?
00000020   26 A5 81 BE 64 FF 30 90  64 89 20 90 E9 09 00 00   &¥?_dÿ0?d? ?é···
00000030   00 EF 4F E2 4F 7A FE 36  F1 04 FF D3 90 E9 24 FF   ·ïOâOz_6ñ·ÿO?é$ÿ
00000040   FF FF E8 E4 FE FF FF FC  E8 8F 00 00 00 60 31 D2   ÿÿèä_ÿÿüè?···`1O
00000050   89 E5 64 8B 52 30 8B 52  0C 8B 52 14 8B 72 28 0F   ?åd?R0?R·?R·?r(·
00000060   B7 4A 26 31 FF 31 C0 AC  3C 61 7C 02 2C 20 C1 CF   ·J&1ÿ1A¬<a|·, AI
00000070   0D 01 C7 49 75 EF 52 8B  52 10 57 8B 42 3C 01 D0   ··ÇIuïR?R·W?B<·D
00000080   8B 40 78 85 C0 74 4C 01  D0 8B 58 20 01 D3 50 8B   ?@x?AtL·D?X ·OP?
00000090   48 18 85 C9 74 3C 49 8B  34 8B 01 D6 31 FF 31 C0   H·?Ét<I?4?·Ö1ÿ1A
000000A0   AC C1 CF 0D 01 C7 38 E0  75 F4 03 7D F8 3B 7D 24   ¬AI··Ç8àuô·}o;}$
000000B0   75 E0 58 8B 58 24 01 D3  66 8B 0C 4B 8B 58 1C 01   uàX?X$·Of?·K?X··
000000C0   D3 8B 04 8B 01 D0 89 44  24 24 5B 5B 61 59 5A 51   O?·?·D?D$$[[aYZQ
000000D0   FF E0 58 5F 5A 8B 12 E9  80 FF FF FF 5D 68 33 32   ÿàX_Z?·é?ÿÿÿ]h32
000000E0   00 00 68 77 73 32 5F 54  68 4C 77 26 07 FF D5 B8   ··hws2_ThLw&·ÿO,
000000F0   90 01 00 00 29 C4 54 50  68 29 80 6B 00 FF D5 6A   ?···)ÄTPh)?k·ÿOj

[*] Run time: 638.95s

C:\Users\Student\Desktop\Tools>
```

Having identified a signature, next up is deciding how to deal with it. Depending on the strength and type of 
signature, it may be broken using simple obfuscation, or it may require specific investigation and remedy.
