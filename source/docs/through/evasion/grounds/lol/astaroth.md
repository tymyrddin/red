# Challenge: Astaroth

In 2017, The Windows Defender Advanced Threat Protection (Windows Defender ATP) Research Team discovered Fileless malware named Astaroth. A fileless malware means that the malware runs and is executed in the system without writing to disk. The malware performs all its functions from the victim device's memory.

Astaroth is known as an information stealer, which takes sensitive information from victim users, such as account credentials, keystrokes, and other data, and sends it to the attacker. The malware relies on various advanced techniques such as anti-debugging, anti-virtualisation, anti-emulation tricks, process hollowing, NTFS Alternate Data Streams (ADS), and Living off the land binaries to perform different functions. 

In the initial access stage, attackers rely on a spam campaign that contains malicious attachment files. The attached file is an LNK file shortcut that, once the victim has clicked it, will result in the following:

* A WMIC command is executed to download and run Javascript code.
* Abusing the BITSadmin to download multiple binaries from the command and control server. Interestingly, in some cases, the malware uses YouTube channel descriptions to hide their C2 server commands.
* Using the BITSadmin, ADS technique, to hide their binaries within the system for their persistence.
* A Certutil tool is used to decode a couple of downloaded payloads into DLL files.
* The DLL files are executed using Regsvr32.

## Resources

* [Astaroth: Banking Trojan](https://www.armor.com/resources/threat-intelligence/astaroth-banking-trojan/)
* [Microsoft Discovers Fileless Malware Campaign Dropping Astaroth Info Stealer](https://www.trendmicro.com/vinfo/de/security/news/cybercrime-and-digital-threats/microsoft-discovers-fileless-malware-campaign-dropping-astaroth-info-stealer)
* [Astaroth malware hides command servers in YouTube channel descriptions](https://www.zdnet.com/article/astaroth-malware-hides-command-servers-in-youtube-channel-descriptions/)

