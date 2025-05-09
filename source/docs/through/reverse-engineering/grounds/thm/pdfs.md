| ![REMnux](/_static/images/remnux-room-banner.png)
|:--:|
| [THM Room: REMnux](https://tryhackme.com/room/malremnuxv2) |

# Analysing malicious pdfs

PDFs can contain code that can be executed without the user's knowledge:

* Javascript
* Python
* Executables
* Powershell Shellcode

## Questions

**How many types of categories of `Suspicious elements` are there in `notsuspicious.pdf`**

```text
remnux@thm-remnux:~/Tasks/3$ peepdf notsuspicious.pdf 
Warning: PyV8 is not installed!!File: notsuspicious.pdf
MD5: 2992490eb3c13d8006e8e17315a9190e
SHA1: 75884015d6d984a4fcde046159f4c8f9857500ee
SHA256: 83fefd2512591b8d06cda47d56650f9cbb75f2e8dbe0ab4186bf4c0483ef468a
Size: 28891 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 18
Streams: 3
URIs: 0
Comments: 0
Errors: 0Version 0:
        Catalog: 1
        Info: 7
        Objects (18): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
        Streams (3): [4, 15, 18]
                Encoded (2): [15, 18]
        Objects with JS code (1): [6]
        Suspicious elements:
                /OpenAction (1): [1]
                /JS (1): [6]
                /JavaScript (1): [6]
```

**Use peepdf to extract the javascript from `notsuspicious.pdf`. What is the flag?**

```text
remnux@thm-remnux:~/Tasks/3$ echo ‘extract js > javascript-from-demo_notsuspicious.pdf’ > extracted_javascript.txt
remnux@thm-remnux:~/Tasks/3$ peepdf -s extracted_javascript.txt demo_notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ cat javascript-from-demo_notsuspicious.pdf 
// peepdf comment: Javascript code located in object 6 (version 0)app.alert("THM{Luckily_This_Isn't_Harmful}");
```
**How many types of categories of `Suspicious elements` are there in `advert.pdf`**

```text
remnux@thm-remnux:~/Tasks/3$ peepdf advert.pdf 
Warning: PyV8 is not installed!!File: advert.pdf
MD5: 1b79db939b1a77a2f14030f9fd165645
SHA1: e760b618943fe8399ac1af032621b6e7b327a772
SHA256: 09bb03e57d14961e522446e1e81184ca0b4e4278f080979d80ef20dacbbe50b7
Size: 74870 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 2
Objects: 29
Streams: 6
URIs: 0
Comments: 0
Errors: 1Version 0:
        Catalog: 1
        Info: 9
        Objects (22): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
        Compressed objects (7): [10, 11, 12, 13, 14, 15, 16]
        Streams (5): [4, 17, 19, 20, 22]
             Xref streams (1): [22]
             Object streams (1): [17]
             Encoded (4): [4, 17, 19, 22]
        Suspicious elements:
             /Names (1): [13]Version 1:
        Catalog: 1
        Info: 9
        Objects (0): []
        Streams (0): []Version 2:
        Catalog: 1
        Info: 9
        Objects (7): [1, 3, 24, 25, 26, 27, 28]
        Streams (1): [26]
             Encoded (1): [26]
        Objects with JS code (1): [27]
        Suspicious elements:
             /OpenAction (1): [1]
             /Names (2): [24, 1]
             /AA (1): [3]
             /JS (1): [27]
             /Launch (1): [28]
             /JavaScript (1): [27]
```

**Now use peepdf to extract the javascript from `advert.pdf`. What is the value of `cName`?**

```text
remnux@thm-remnux:~/Tasks/3$ echo ‘extract js > javascript-from-advert.pdf’ > extracted_javascript.txt
remnux@thm-remnux:~/Tasks/3$ peepdf -s extracted_javascript.txt advert.pdf
remnux@thm-remnux:~/Tasks/3$ cat javascript-from-advert.pdf 
// peepdf comment: Javascript code located in object 27 (version 2)this.exportDataObject({
    cName: "notsuspicious",
    nLaunch: 0```
```

Still, the `advert.pdf` actually does have an embedded executable. View the extracted Javascript. 
When the PDF is opened, the user will be asked to save an attachment.
