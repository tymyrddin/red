# Diffie-Hellman

Prior to Diffie–Hellman, establishing a shared secret required performing tedious procedures such as manually exchanging sealed envelopes. Once communicating parties have established a shared secret value with the DH protocol, that secret can be used to establish a secure channel by turning the secret into one or more symmetric keys that are then used to encrypt and authenticate subsequent communication. The DH protocol (and its variants) are therefore called key agreement protocols.

* Choose a prime $p$ and a generator $g ∈ \mathbb{F}_p$
* Alice picks a private key $a ∈ \mathbb{Z}_{p−1}$
* Bob picks a private key $b ∈ \mathbb{Z}_{p−1}$
* Alice's public key is $g^a \mod p$
* Bob's public key is $g^a \mod p$
* Their shared key is $g^{ab} ≡ (g^a)^b ≡ (g^b)^a \mod p$

Diffie–Hellman’s simplicity can be deceiving. For one thing, it won’t work with just any prime $p$ or base number $g$. For example, some values of $g$ will restrict the shared secrets $g^{ab}$ to a small subset of possible values, whereas you’d expect to have about as many possible values as elements in $\mathbb{Z}_p^*$ , and therefore as many possible values for the shared secret. 

To ensure the highest security, safe DH parameters should work with a prime $p$ such that $(p – 1) / 2$ is also prime. Such a safe prime guarantees that the group does not have small subgroups that would make DH easier to break.

The `dhparam` command of the OpenSSL toolkit will only generate safe DH parameters, but the extra checks built into the algorithm result increase the execution time considerably.

## What can possibly go wrong?

Diffie–Hellman protocols can fail spectacularly in a variety of ways.

* Not hashing the shared secret
* Using legacy Diffie–Hellman: The TLS protocol is the security behind HTTPS secure websites as well as the secure mail transfer protocol (SMTP). TLS takes several parameters, including the type of Diffie–Hellman protocol it will use, though most TLS implementations still support anonymous DH for legacy reasons, despite its insecurity.
* Unsafe group parameters: In January 2016, the maintainers of the OpenSSL toolkit fixed a high-severity vulnerability ([CVE-2016-0701](https://nvd.nist.gov/vuln/detail/CVE-2016-0701)) that allowed an attacker to exploit unsafe Diffie–Hellman parameters. The root cause of the vulnerability was that OpenSSL allowed users to work with unsafe DH group parameters (namely, an unsafe prime p) instead of throwing an error and aborting the protocol altogether before performing any arithmetic operation.



