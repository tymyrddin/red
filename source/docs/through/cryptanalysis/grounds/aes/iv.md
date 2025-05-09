# Initialisation vector

[RootMe challenge](https://www.root-me.org/en/Challenges/Cryptanalysis/Initialisation-Vector): The Initialisation Vector has been lost, we unfortunately just found a ciphertext. It’s up to you to find this lost IV using this information. The text was encrypted using AES-256 CBC, and the padding used is PKCS#7 standard.

The validation password is the initial vector (ASCII).

Plaintext:

```text
Marvin: "I am at a rough estimate thirty billion times more intelligent than you. Let me give you an example. Think of a number, any number."
Zem: "Er, five."
Marvin: "Wrong. You see?"
```

Ciphertext:

    cY1Y1VPXbhUqzYLIOVR0RhUXD5l+dmymBfr1vIKlyqD8KqHUUp2I3dhFXgASdGWzRhOdTj8WWFTJ
    PK0k/GDEVUBDCk1MiB8rCmTZluVHImczlOXEwJSUEgwDHA6AbiCwyAU58e9j9QbN+HwEm1TPKHQ6
    JrIOpdFWoYjS+cUCZfo/85Lqi26Gj7JJxCDF8PrBp/EtHLmmTmaAVWS0ID2cJpdmNDl54N7tg5TF
    TrdtcIplc1tDvoCLFPEomNa5booC

Key:

    AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRqrHB0eHyA=


1. Decrypt the ciphertext with a `NULL` IV to find a string that does not appear in the original plaintext (the first 16 characters):

```text
0x3e04461e5d1f6365305015507f5d5d5b
```

2. `XOR` the first block (16 characters) of the deciphered ciphertext, with the actual plaintext.