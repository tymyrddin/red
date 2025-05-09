# DCC2 Hash

After 2003, Vista Servers use `MSCACHEV2` or `DCC2` to store previous logon information of users locally.

[Retrieve the password of the Administrator user from the information output by the secretsdump tool of the Impacket suite](https://www.root-me.org/en/Challenges/Cryptanalysis/Hash-DCC2).

```text
[*] Target system bootKey: 0xf1527e4742bbac097f937cc4ac8508e4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ASPNET:1025:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DBAdmin:1028:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sshd:1037:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
service_user:1038:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
ROOTME.LOCAL/PODALIRIUS:$DCC2$10240#PODALIRIUS#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/SHUTDOWN:$DCC2$10240#SHUTDOWN#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/Administrator:$DCC2$10240#Administrator#23d97555681813db79b2ade4b4a6ff25
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
ROOTME\PC01$:aes256-cts-hmac-sha1-96:e6d5ab8e29fb4f648490fb1cb099b64dffbd2b9e77d46b8df41bc482d590bfe3
ROOTME\PC01$:aes128-cts-hmac-sha1-96:971589d11f2a62980fcab210fa442f4a
ROOTME\PC01$:des-cbc-md5:f18f6dfb6b197fe9
ROOTME\PC01$:plain_password_hex:a918646aa8406975d5ed97534946ef780d48075e618e309b30bf5c9f
ROOTME\PC01$:88c2213866d15f645295e3ebc8779879:ba380afe874fbc0d99b16f8188968133:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xf35c35eddeecd7b0da287db2e4f8b89b96387157
dpapi_userkey:0x04b4fb8214fb142f86ca2c34de1866f7e565f6f1
[*] NL$KM
 0000   E4 7B 83 10 D7 9D A9 FE  C5 B7 F9 CB 81 27 2A 13   .{...........'*.
 0010   9B 61 D1 F2 9C 0B 1C 8C  53 55 42 46 02 51 10 AC   .A......SUBF.Q..
 0020   4C 02 88 83 CF 37 C8 0C  D3 16 71 96 9E 0E B5 46   L....7....Q....F
 0030   C5 A4 D0 26 8A 77 40 85  B2 E6 1A 8D CF CB A3 46   ...&.W@........F
NL$KM:e47b8310d79da9fec5b7f9cb81272a139b61d1f29c0b1c8c53554246025110ac4c028883cf37c80cd31671969e0eb546c5a4d0268a774085b2e61a8dcfcba346
[*] _SC_sos_scheduler_scibeta
ELITE\CHOUPAPI:Mdp!1256@
[*] _SC_sshd
service_user:Mdp!1256@
[*] Cleaning up...
```

Put `$DCC2$10240#Administrator#23d97555681813db79b2ade4b4a6ff25` in a file, for example `hash.txt`.

And use `hashcat` or `john` to get the `Administrator` password:

```text
hashcat -a 0 -m 2100 hash.txt /usr/share/wordlists/rockyou.txt
```

```text
hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz, 14853/29770 MB (4096 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 2100 (Domain Cached Credentials 2 (DCC2), MS Cache 2)
Hash.Target......: $DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
Time.Started.....: Sat Mar  4 02:32:54 2023 (7 secs)
Time.Estimated...: Sat Mar  4 02:33:01 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    24758 H/s (12.01ms) @ Accel:512 Loops:512 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 151552/14344384 (1.06%)
Rejected.........: 0/151552 (0.00%)
Restore.Point....: 147456/14344384 (1.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9728-10239
Candidate.Engine.: Device Generator
Candidates.#1....: mckenzy -> armas
Hardware.Mon.#1..: Temp: 72c Util: 92%

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Sat Mar  4 02:32:31 2023
Stopped: Sat Mar  4 02:33:02 2023
```
