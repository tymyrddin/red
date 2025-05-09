# Security goals

_A cipher is secure if, even given a large number of plaintext–ciphertext pairs, nothing can be learnt about the cipher’s behaviour when applied to other plaintexts or ciphertexts._

What can be "learnt" and what is a "cipher's behaviour"? Security goals are descriptions of what is considered a successful attack. Cryptographers define two main security goals that correspond to different ideas of what it means to learn something about a cipher's behaviour.

## Indistinguishability (IND)

Ciphertexts should be indistinguishable from random strings. This is usually illustrated with a hypothetical game: if an attacker picks two plaintexts and then receives a ciphertext of one of the two (chosen at random), they shouldn’t be able to tell which plaintext was encrypted, even by performing encryption queries with the two plaintexts (and decryption queries, if the model is CCA rather than CPA).

## Non-malleability (NM)

Given a ciphertext $C_1 = E(K, P_1)$, it should be impossible to create another ciphertext, $C_2$, whose corresponding plaintext, $P_2$, is related to $P_1$ in a meaningful way (for example, to create a $P_2$ that is equal to $P_1 ⊕ 1$ or to $P_1 ⊕ X$ for some known value $X$). 

Surprisingly, the one-time pad is malleable: given a ciphertext $C1 = P 1 ⊕ K$, you can define $C_2 = C_1 ⊕ 1$, which is a valid ciphertext of $P_2 = P_1 ⊕ 1$ under the same key $K$. Oops.

Security goals are only useful when combined with an attack model. The convention is to write a security notion as GOAL-MODEL. For example, IND-CPA denotes indistinguishability against chosen-plaintext attackers, NM-CCA denotes nonmalleability against chosen-ciphertext attackers, and so on.

## Semantic security (IND-CPA)

The Semantic security notion captures the intuition that ciphertexts should not leak any information about plaintexts as long as the key is secret. To achieve IND-CPA security, encryption must return different ciphertexts if called twice on the same plaintext; otherwise, an attacker could identify duplicate plaintexts from their ciphertexts, contradicting the definition that ciphertexts shouldn’t reveal any information.

One way to achieve IND-CPA security is to use randomised encryption:_With randomised encryption, ciphertexts must be slightly longer than plaintexts in order to allow for more than one possible ciphertext per plaintext. For example, if there are $2^{64}$ possible ciphertexts per plaintext, ciphertexts must be at least 64 bits longer than plaintexts._

One of the simplest constructions of a semantically secure cipher uses a deterministic random bit generator (DRBG), an algorithm that returns randomlooking bits given some secret value:

\begin{align} E(K,R,P) = ( DRBG ( K || R ) \oplus P , R ) \end{align}
 
Here, $R$ is a string randomly chosen for each new encryption and given to a DRBG along with the key ($K || R$ denotes the string consisting of $K$ followed by $R$). This approach is reminiscent of the one-time pad: instead of picking a random key of the same length as the message, we leverage a random bit generator to get a random-looking string. 

The proof that this cipher is IND-CPA secure is simple, if we assume that the DRBG produces random bits. The proof works ad absurdum: if you can distinguish ciphertexts from random strings, which means that you can distinguish $DRBG(K || R) ⊕ P$ from random, then this means that you can distinguish $DRBG(K || R)$ from random. The CPA model lets you get ciphertexts for chosen values of $P$, so you can `XOR` $P$ to $DRBG(K, R) ⊕ P$ and get $DRBG(K, R)$. This is a contradiction, because we started by assuming that $DRBG(K, R)$ can not be distinguished from random, producing random strings. The conclusion therefore is that ciphertexts can not be distinguished from random strings, and therefore that the cipher is secure.

## Asymmetric encryption

The attack models and security goals for asymmetric encryption are about the same as for symmetric encryption, except that because the encryption key is public, any attacker can make encryption queries by using the public key to encrypt. The default model for asymmetric encryption is therefore the chosen-plaintext attacker (CPA).

Symmetric and asymmetric encryption are the two main types of encryption, and they are usually combined to build secure communication systems. They’re also used to form the basis of more sophisticated schemes.

## Resources

* [Probabilistic Encryption and How to Play Mental Poker Keeping Secret All Partial Information, by Goldwasser and Micali](https://docslib.org/doc/11410128/how-to-play-mental-poker-keeping-secret-all-partial-information)
* [Serious Cryptography - A Practical Introduction to Modern Encryption by Jean-Philippe Aumasson](https://nostarch.com/seriouscrypto)