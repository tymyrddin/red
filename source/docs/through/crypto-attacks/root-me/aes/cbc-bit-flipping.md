# CBC Bit-flipping attack

[RootMe Challenge: Flip it](https://www.root-me.org/en/Challenges/Cryptanalysis/AES-CBC-Bit-Flipping-Attack): An elite hacker team is sharing tools.
Some tools seem interesting, but you need to join their team to access them.

[bit_flipping_attack.py](https://github.com/tymyrddin/scripts-modern-ciphers/blob/main/rootme/bit_flipping_attack.py)

* [The Block Cipher SQUARE - Daemen, Knudsen, Rijmen](https://repository.root-me.org/Cryptographie/Sym%C3%A9trique/EN%20-%20The%20Block%20Cipher%20SQUARE%20-%20Daemen,%20Knudsen,%20Rijmen.pdf)
* [SANS Institute AES CBC Bit Flipping](https://www.root-me.org/en/Challenges/Cryptanalysis/AES-CBC-Bit-Flipping-Attack)

## Counter moves

CBC bit-flipping rewrites plaintext because the mode carries no integrity. Authenticated encryption such as AES-GCM removes the malleability. Defenders' notes on this are under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
