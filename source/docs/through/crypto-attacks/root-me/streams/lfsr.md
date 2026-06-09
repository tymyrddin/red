# LFSR - Known plaintext

[RootMe: LFSR - Known plaintext](https://www.root-me.org/en/Challenges/Cryptanalysis/LFSR-Known-plaintext?lang=en): One of your friends argues that stream ciphers are safer than ever. You smile and tell him he is not right. Upset, he challenges you by sending you an encrypted file. Show him he’s wrong!

1. The file he sent is named `challenge.png.encrypt`. Apparently it is a `.png`. 
2. The [8 header bytes and 8 IDHR bytes](https://en.wikipedia.org/wiki/PNG) always contain the following hex values: `'89504e470d0a1a0a0000000d49484452'`. A 16 byte plaintext.
3. Get the  script. 16 bytes of ciphertext.
4. XOR the plaintext with the first 16 bytes from `challenge.png.encrypt` and put in comma separated list format:

```text
[1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0]
```

5. Use that in [berlekamp_massey.py](https://github.com/tymyrddin/scripts-modern-ciphers/blob/main/lfsr/berlekamp_massey.py)

```text
Minimal LFSR: 16
Minimal polynomial: [1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]
```

This is the polynomial $X^16 + X^15 + X^13 + X^5 + 1$

6. Use [pylfsr](https://pypi.org/project/pylfsr/) to create an LFSR algorithm, and XOR each encrypted byte with LFSR output to decode the cipher and create an image `challenge.png`. Get the password from the image.

