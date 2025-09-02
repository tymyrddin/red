# Elliptic curve balls

Elliptic Curve Cryptography (ECC) is a family of public-key cryptosystems, based on the algebraic structures of the elliptic curves over finite fields and on the difficulty of the Elliptic Curve Discrete Logarithmic Problem (ECDLP).

Like RSA, ECC multiplies large numbers, but unlike RSA it does so in order to combine points on a mathematical curve, called an elliptic curve. ECC uses smaller keys and signatures than RSA for the same level of security and provides very fast key generation, fast key agreement and fast signatures.

To complicate matters, there are many types of elliptic curves, efficient and inefficient ones, and secure and insecure ones. ECC crypto algorithms can use different underlying elliptic curves. Different curves provide different level of security (cryptographic strength), different performance (speed) and different key length, and also may involve different algorithms.

## Elliptic curves

An elliptic curve is a curve on a plane, a group of points with $x$ and $y$ coordinates. For example, the curve $y = 3$ is a horizontal line with the vertical coordinate 3, curves of the form $y = ax + b$ with fixed numbers $a$ and $b$ are straight lines, $x^2 + y^2 = 1$ is a circle of radius $1$ centreed on the origin, and so on.

An [elliptic curve](https://www.desmos.com/calculator/ialhd71we3) as used in cryptography is typically a curve whose equation is of the form $y^2 = x^3 + ax + b$ (known as the Weierstrass form), where the constants $a$ and $b$ define the shape of the curve, or of the form $x^2 + y^2 = 1 + dx^2y^2$ (Edwards curves).

In ECC, the field is a square matrix of size $p x p$ and the points on the curve are limited to integer coordinates within the field only. All algebraic operations within the field (like point addition and multiplication) result in another point within the field. 

ECC curves, adopted in the popular cryptographic libraries and security standards, have name (named curves, e.g. `secp256k1` or `Curve25519`), field size (which defines the key length, e.g. 256-bit), security strength (usually the field size / 2 or less), performance (operations/sec) and many other parameters.

## ECC keys

The private keys in the ECC are integers (in the range of the curve's field size, typically 256-bit integers).

The key generation in the ECC cryptography is as simple as securely generating a random integer in certain range, so it is extremely fast. Any number within the range is valid ECC private key.

The public keys in the ECC are EC points - pairs of integer coordinates $(x, y)$, on the curve. Due to their special properties, EC points can be compressed to just one coordinate + 1 bit (odd or even). Thus the compressed public key, corresponding to a 256-bit ECC private key, is a 257-bit integer.

## ECC algorithms

Elliptic-curve cryptography (ECC) provides several groups of algorithms, based on the math of the elliptic curves over finite fields:

* ECC digital signature algorithms like ECDSA (for classical curves) and EdDSA (for twisted Edwards curves).
* ECC encryption algorithms and hybrid encryption schemes like the ECIES integrated encryption scheme and EEECC (EC-based ElGamal).
* ECC key agreement algorithms like ECDH, X25519 and FHMQV.

## ECDH

ECDH is to the ECDLP problem what DH is to DLP: it’s secure as long as ECDLP is hard. DH protocols that rely on DLP can therefore be adapted to work with elliptic curves and rely on ECDLP as a hardness assumption.

The output from [ecc-based-key-derivation.py](https://github.com/tymyrddin/scripts-modern-ciphers/blob/main/ecc/ecc-based-key-derivation.py):

```text
Private key: 0x56654dafa1ac13a3d54cf6edeef33852a0a74418ca1a1d7180c25213976759fa
Public key: 0x1d02eb6437a4e32037324bb2925c87bc84b2fd71a565268242ed8259515921fe0
Ciphertext public key: 0x9df7d5d762ee6a8018613eb3644ee7a21fd811cfa7f4167628a255c40db126ac0
Encryption key: 0x3c94844f84d94d280725701f7d18c2f6b463a04c0f7dfaf208d48e0fabd7122e1
Decryption key: 0x3c94844f84d94d280725701f7d18c2f6b463a04c0f7dfaf208d48e0fabd7122e1
```

## ECDSA

The standard algorithm used for signing with ECC is ECDSA, which stands for elliptic curve digital signature algorithm. This algorithm has replaced RSA signatures and classical DSA signatures in many applications. It is, for example, the only signature algorithm used in Bitcoin and is supported by many TLS and SSH implementations.

As with all signature schemes, ECDSA consists of a signature generation algorithm that the signer uses to create a signature using their private key and a verification algorithm that a verifier uses to check a signature’s correctness given the signer’s public key. The signer holds a number, $d$, as a private key, and verifiers hold the public key, $p = dG$. Both know in advance what elliptic curve to use, its order ($n$, the number of points in the curve), and the coordinates of a base point, $G$.

## What can possibly go wrong?

Elliptic curves have their downsides due to their complexity and large attack surface. Their use of more parameters than classical Diffie–Hellman brings with it a greater attack surface with more opportunities for mistakes and abuse, and possible software bugs that might affect their implementation.

Elliptic curve software may also be vulnerable to side-channel attacks due to the large numbers used in their arithmetic. If the speed of calculations depends on inputs, attackers may be able to obtain information about the formulas being used to encrypt.

## Breaking ECDH using another curve

ECDH can be elegantly broken if you fail to validate input points. The primary reason is that the formulas that give the coordinates for the sum of points $p + q$ never involve the $b$ coefficient of the curve; instead, they rely only on the coordinates of $p + q$ and the $a$ coefficient (when doubling a point). The unfortunate consequence of this is that when adding two points, you can never be sure that you’re working on the right curve because you may actually be adding points on a different curve with a different $b$ coefficient. That means ECDH can be broken with the so-called **invalid curve attack**.

## ECDSA with bad randomness

ECDSA signing is randomised, as it involves a secret random number $k$ when setting $s = (h + rd) / k \mod n$. But if the same $k$ is reused to sign a second message, an attacker could combine the resulting two values, $s_1 = (h_1 + rd) / k$ and $s_2 = (h_2 + rd) / k$, to get $s_1 – s_2 = (h_1 – h_2) / k$ and then
$k = (h_1 – h_2) / (s_1 – s_2)$. When $k$ is known, the private key $d$ is easily recovered by computing $(ks_1 − h_1)/r = ((h_1 + rd ) − h_1)/r = rd/r = d$.

## RootMe challenges

* [Discrete logarithm problem](../grounds/ecc/discrete-log.md)
