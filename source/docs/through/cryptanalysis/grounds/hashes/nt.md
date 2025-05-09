# NT Hash

This is the way passwords are stored on modern Windows systems. They can be obtained by dumping the SAM database, or using Mimikatz. They are also stored on domain controllers in the NTDS file. These are the hashes that can be used to [pass-the-hash](https://ad.tymyrddin.dev/docs/pivot/auth.html#pass-the-hash).

[Retrieve the password of the Administrator user from the information output by the secretsdump tool of the Impacket suite](https://www.root-me.org/en/Challenges/Cryptanalysis/Hash-NT).

```text
[*] Target system bootKey: 0xf1527e4742bbac097f937cc4ac8508e4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4f79698831d92b61f886438e36c0c52:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ASPNET:1025:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DBAdmin:1028:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sshd:1037:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
service_user:1038:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
ROOTME.LOCAL/PODALIRIUS:$DCC2$10240#PODALIRIUS#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/SHUTDOWN:$DCC2$10240#SHUTDOWN#9d3e8dbe4d9816fa1a5dda431ef2f6f1
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

Crack `b4f79698831d92b61f886438e36c0c52` with  `john` or `hashcat`:

    john --format=nt hash.txt
    hashcat -m 1000 -a 3 hash.txt

Or use [hashes.com](https://hashes.com/en/decrypt/hash).
