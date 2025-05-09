# SHA-3 Hash

[RootMe Challenge: Hash - SHA-3 Reverse the Keccak algorithm](https://www.root-me.org/en/Challenges/Cryptanalysis/Hash-SHA-3): You just got a SHA-3 hash:

```text
0d 6e 57 75 05 f5 0c ac 98 85 e3 1a 70 da 8b b4
7c 59 dd 77 1e 7d 72 2e 13 94 9d 69 2e 60 7b 98
e3 6f b2 b9 21 76 1c a3 7f 94 fb c2 fa 28 40 bb
fe dd 82 5e 4f 65 b5 18 7d 0d 88 34 20 35 2b e3
```

You also have a stack dump at the end of the function that generated this hash. Find the text that produced this hash.

SHA-3 was not designed to replace SHA-2. It was the result of a contest to design a new hashing algorithm. The actual algorithm was named Keccak designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. The United States NIST (National Institute of Standards) published FIPS 202 standardizing the use of SHA-3.

Unlike SHA-1 and SHA-2 that use a Merkle-Damgard construction, SHA-3 uses a sponge construction, a type of algorithm which uses an internal state and takes input of any size producing a specific sized output. This makes it a good fit for cryptographic hashes which need to take variable length input and produce a fixed-length output.