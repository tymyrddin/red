# PNG PVD

[root-me challenge](https://www.root-me.org/en/Challenges/Steganography/PNG-Pixel-Value-Differencing): Extract the hidden message from the image. SHA1: `06897894d602407321092489afeb84956ae2fd66`.

----

````text
┌──(kali㉿kali)-[~/Downloads]
└─$ stegopvd extract ch12.png -z       
                                    _                                 _
                                ___| |_ ___  __ _  ___  _ ____   ____| |                               
                               / __| __/ _ \/ _` |/ _ \| '_ \ \ / / _` |                               
                               \__ \ ||  __/ (_| | (_) | |_) \ V / (_| |                               
                               |___/\__\___|\__, |\___/| .__/ \_/ \__,_|                               
                                            |___/      |_|                                             
                                                                                                       
                                                                                                       
                                                                                                       
04:40:21 [INFO] Hidden data:
The pixel-value differencing (PVD) scheme uses the difference value between two consecutive pixels in a block to determine how many secret bits should be embedded. There are two types of the quantization range table in Wu and Tasi's method. This is a a Steganographic Method Based on Pixel-Value Differencing and the Perfect Square Number. Flag is PvD:Pl4tiNuMvSDi4m0nd :)
````
