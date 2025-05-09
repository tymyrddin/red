# Attack models

_A cipher is secure if, even given a large number of plaintext–ciphertext pairs, nothing can be learnt about the cipher’s behaviour when applied to other plaintexts or ciphertexts._

How does an attacker come by these pairs? How large is a "large number"? Attack models are assumptions about what an attacker can and cannot do.

## Black-box models

These are some useful attack models expressed in terms of what an attacker can observe and what queries they can make to the cipher. An encryption query, for example, takes a plaintext and returns a corresponding ciphertext, without revealing the secret key.

### Ciphertext-only

Ciphertext-only attack (COA) is a type of attack model in which the attacker only knows the ciphertext and has no knowledge of the associated plaintext, and don’t know how the plaintexts were selected. Attackers in the COA model are passive and can’t perform encryption or decryption queries. In the history of cryptography, early ciphers, implemented using pen-and-paper, were routinely broken using ciphertexts alone.

In this attack model, the attacker gains access to a collection of ciphertext. Although the plaintext can still not be read, it is theoretically possible to determine the ciphertext from the collection. On occasion, it works. 

A one time pad (OTP) can not be broken because there are many answers (that make sense) given a specific ciphertext, so there is no way to know the intended plaintext. In practice, an attacker usually has at least some knowledge of the plaintext, like the set of characters used or the language used.

### Known-plaintext

In known-plaintext attacks (KPA), an attacker has access to the ciphertexts and its corresponding plaintexts. Attackers in the KPA model thus have a list of plaintext–ciphertext pairs, where plaintexts are assumed to be randomly selected. KPA is a passive attacker model.

The goal is to guess the secret key (or a number of secret keys), or to develop an algorithm which would allow for decrypting further messages. The attacker can not actively change the data or secret keys to be processed by the cipher.

This type of attack is useful when finding or knowing the plaintext of some portions of the ciphertext using information gathering techniques.

For example, known-plaintext attacks were used for attacking the ciphers used during the Second World War, like the attacks on German Enigma ciphers. The English intelligence targeted some common phrases, commonly appearing in encrypted German messages, like weather forecasts or geographical names.

The ancient and simple `XOR` cipher of the early digital days, can also easily be broken by knowing only some parts of plaintext and corresponding encrypted messages.

Modern ciphers are generally resistant against purely known-plaintext attacks, save for the [old encryption method used in the PKZIP application](../grounds/data/pkzip.md). Having just one copy of encrypted file, together with its original version, it was possible to completely recover the secret key.

### Chosen-plaintext

In a chosen-plaintext attack (CPA), an adversary can (possibly adaptively) ask for the ciphertexts of arbitrary plaintext messages. This is formalised by allowing the adversary to interact with an encryption oracle, viewed as a black box. Unlike COA or KPA, which are passive models, CPA are active attackers, because they influence the encryption processes rather than passively eavesdropping.

The goal is to reveal all or part of the secret encryption key:

1. Choose a set of plaintexts and submit once to the oracle (batch chosen-plaintext attack)
2. Choose a smaller one, receive its encrypted ciphertext and then based on the answer, choose another one (when having the capability to choose plaintext for encryption many times and instead of using one big block of text) (adaptive chosen plaintext attack)

It may seem infeasible in practice that an attacker could obtain ciphertexts for given plaintexts, but modern cryptography is implemented in software or hardware and is used in a diverse range of applications, making it very feasible. Chosen-plaintext attacks become extremely important in the context of public key cryptography, where the encryption key is public and attackers can encrypt any plaintext they choose.

Chosen-plaintext attacks are often used to break symmetric encryption. Thus, it is important for symmetric cipher implementers to understand how an attacker would attempt to break their cipher (and make improvements based on that).

For some chosen-plaintext attacks, only a small part of the plaintext may need to be chosen by the attacker; such attacks are known as plaintext injection attacks.

### Oracles

A cryptographic oracle is a mathematical description of a data leak, to be used in security proofs. Given access to such an oracle, it is possible to rebuild the private key. For example, in the old (1999) case of RSA, it meant that knowing whether a value has a proper padding or not is equivalent to learning the private key (after a million or so tries). The [Bleichenbacher's attack](https://asecuritysite.com/encryption/c_c3) showed that it also works the other way round.

In cryptographic papers oracles are often used to show that, even if adversaries would have access to an oracle, they still wouldn't have any (significant) advantage for breaking security. For example, one important property of encryption algorithms (called resistance to known plaintext attacks) is that if an attacker is given a message encrypted with a key `m'` and they want to know the original message `m` (or figure out the key), then giving them another message `n` and its encryption with a key `n'` should not help them do so.

### Chosen ciphertext

In a chosen-ciphertext attack (CCA), an adversary can analyse chosen ciphertexts together with their corresponding plaintexts to acquire a secret key or to get as much information about the system as possible. 

In this attack, the adversary is assumed to have a way to trick someone who knows the secret key into decrypting arbitrary message blocks and send back the result. The attacker can choose some arbitrary nonsense as an **encrypted message** and ask to see the (usually) different nonsense it decrypts to, and can do this a number of times. The goal of the adversary is deducing what the secret key is.

1. Replace or modify a ciphertext to be sent on a device.
2. Eavesdrops on the communications.
3. Work out what the receiver read when he/she decrypted the fake ciphertext.

Chosen-ciphertext attacks are usually used for breaking systems with public key encryption. Early versions of the RSA cipher were vulnerable to such attacks. They are hardly used for attacking systems protected by symmetric ciphers, but some self-synchronising stream ciphers can also be attacked successfully.

An adaptive chosen-ciphertext attack (CCA2) is an interactive form of chosen-ciphertext attack in which an adversary first sends a number of ciphertexts to be decrypted chosen adaptively, then uses the results to distinguish a target ciphertext without consulting the encryption oracle on the challenge ciphertext. There exist rather few practical adaptive-chosen-ciphertext attacks. This model is mostly used for analysing the security of a given system. 

Proving that this attack doesn't break the security confirms that any realistic chosen-ciphertext attack is unlikely to succeed. In an adaptive attack the attacker is allowed adaptive queries after the target is revealed (but the target query is disallowed). In an indifferent (non-adaptive) chosen-ciphertext attack (CCA1), the second stage of adaptive queries is not allowed. 

## Gray-box models

In a gray-box model, the attacker has access to a cipher’s implementation. This makes gray-box models more realistic than black-box models for applications such as smart cards, embedded systems, and virtualized systems, to which attackers often have physical access and can thus tamper with the algorithms' internals. Gray-box models are more difficult to define than black-box ones because they depend on physical, analog properties rather than just on an algorithm's input and outputs, and crypto theory will often fail to abstract the complexity of the real world.

### Side-channel (non-invasive)

A side-channel attack (SCA) is a security exploit that involves collecting information about what a computing device does when it is performing cryptographic operations.

Examples of side-channels are sound, infrared radiation, time delays, power consumption, and electromagnetic radiation. This "leaked information" may be statistically related to the underlying computations or keys, giving clues that are useful to an attacker.

### Possiblilities

1. Monitor the emissions produced by electronic circuits when the target's computer is being used to exploit information about power consumption and electromagnetic fields for reverse engineering (side-channel attack)
2. Use the sounds a central processing unit (CPU) produces (acoustic attack) 
3. Exploits how and when cache is accessed (cache attack)
4. Use information by introducing faults into the system’s computations (differential fault analysis attack)
5. Monitor the movement of data to and from a system's CPU and memory (timing attack, 
    for example AES side-channel attack)
6. Use infrared images to monitor the surface of a CPU chip (thermal-imaging attack)
7. Collect information about hard disk activity by using a audio/visual recorder (optical side-channel attack)
8. Monitor the electromagnetic fields produced by data as it moves through the computer (Van Eck phreaking)

### Fault (semi-invasive)

A variety of fault attacks exist, where some hardware fault (an unexpected condition or defect) leads to a processing mistake that is beneficial to the attacker. Fault attacks might overlap with physical tampering. Methods of inducing faults include: supplying noisy power or clock signals, incorrect voltage, excessive temperature, radiation or high energy beams such as UV, laser, etc.

### Physical tampering (invasive)

Invasive attacks are a family of attacks on cipher implementations that are more powerful than side-channel attacks, and more expensive because they require sophisticated equipment. You can run basic side-channel attacks with a standard PC and an off-the-shelf oscilloscope, but invasive attacks require tools such as a high-resolution microscopes and a chemical lab.

Invasive attacks consist of a whole set of techniques and procedures, from using nitric acid to remove a chip’s packaging to remove protective layers and gain access to chip internals, to microscopic imagery acquisition, partial reverse engineering, and possible modification of the chip’s behaviour with something like laser fault injection.

## Resources

* [Serious Cryptography - A Practical Introduction to Modern Encryption by Jean-Philippe Aumasson](https://nostarch.com/seriouscrypto)
* [Text Characterisation](http://www.practicalcryptography.com/cryptanalysis/text-characterisation/)
* [All About Side Channel Attacks](https://repository.root-me.org/Cryptographie/EN%20-%20All%20about%20side%20channel%20attacks%20-%20Nicolas%20Courtois.pdf)

