# PNG PIT

[root-me challenge](https://www.root-me.org/en/Challenges/Steganography/PNG-Pixel-Indicator-Technique): Find the hidden message in this image. SHA1 hash: `52062f33b7a58050c082a5f677a1ae626da32d88`.

----

```text                                                                                             
┌──(kali㉿kali)-[~/Downloads]
└─$ stegopit -v -i G ch13.png                                         
                                     _                         _ _
                                 ___| |_ ___  __ _  ___  _ __ (_) |_                                  
                                / __| __/ _ \/ _` |/ _ \| '_ \| | __|                                 
                                \__ \ ||  __/ (_| | (_) | |_) | | |_                                  
                                |___/\__\___|\__, |\___/| .__/|_|\__|                                 
                                             |___/      |_|                                           
                                                                                                      
                                                                                                      
                                                                                                      
04:23:24 [DEBUG] Image size: 1000x1000
04:23:24 [DEBUG] RMS:        8296
04:23:24 [DEBUG] N other:    IC=G
04:23:24 [DEBUG] Channels:   GBR
04:23:24 [INFO] Hidden data:
Image based steganography utilize the images as cover media to hide secret data. The common technique used in this field replaces the least significant bits (LSB) of image pixels with intended secret bits. Several improvements to enhance the security of the LSB method have been presented earlier. This paper proposed a new improved technique that takes the advantage of the 24 bits in each pixel in the RGB images using the two least significant bits of one channel to indicate existence of data in the other two channels. The stego method does not depend on a separate key to take out the key management overhead. !!! The flag for this challenge is : "***Flag***". Instead, it is using the size of the secret data as selection criteria for the first indicator channel to insert security randomness. Our proposed technique is analysed using security and capacity measures and compared to two other similar work. This proposed pixel indicator technique for RGB image steganography showed interesting promising result.
```

