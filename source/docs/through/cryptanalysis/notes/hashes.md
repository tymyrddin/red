# Hacking hashes

Hash functions, like MD5, SHA-1, SHA-256, SHA-3, and BLAKE2, are used in digital signatures, public-key encryption, integrity verification, message authentication, password protection, key agreement protocols, and many other cryptographic protocols.

## Security goals

Hash functions in applied cryptography are constructions that were originally defined to provide three specific security properties: 

* Pre-image resistance ensures that no one should be able to reverse the hash function in order to recover the input given an output.
* Second pre-image resistance: if I give you an input and the digest it hashes to, you should not be able to find a different input that hashes to the same digest.
* Collision resistance: one should be able to produce two different inputs that hash to the same output.

This definition has changed over time, and are often meaningless on their own; it all depends on how the hash function is used.

In addition, hash functions are usually designed so that their digests are unpredictable and random. This is useful because one cannot always prove a protocol to be secure.

Many protocols are instead proven in the random oracle model, where a fictional and ideal participant called a random oracle is used. In this type of protocol, one can send any inputs as requests to that random oracle, which is said to return completely random outputs in response, and like a hash function, giving it the same input twice returns the same output twice.

Proofs in this model are sometimes controversial as we do not know for sure if we can replace these random oracles with real hash functions (in practice). Yet, many legitimate protocols are proven secure using this method, where hash functions are seen as more ideal than they probably are.

## Finding collisions

### Naive birthday attack

1. Compute $2^{n/2}$ hashes of $2^{n/2}$ arbitrarily chosen messages and store all the message/hash pairs in a list.
2. Sort the list with respect to the hash value to move any identical hash values next to each other.
3. Search the sorted list to find two consecutive entries with the same hash value.

This method requires a lot of memory (storing $2^{n/2}$ message/hash pairs), and sorting lots of elements slows down the search, requiring about $2^{2n}$ basic operations on average using even the quicksort
algorithm.

### The Rho method

The Rho method is an algorithm for finding collisions that, unlike the naive birthday attack, requires only a small amount of memory:

1. Given a hash function with $n$-bit hash values, pick some random hash value ($H_1$), and define $H_1 = H'_1$.
2. Compute $H_2 =  Hash(H_1)$, and $H'_2 = Hash(Hash(H'_1))$; that is, in the first case apply the hash function once, and in the second case twice.
3. Iterate the process and compute $H_i + 1 = Hash(H_i)$, $H'_i + 1 = Hash(Hash(H'_i))$, until you reach $i$ such that $H_i + 1 = H'_i + 1$.

![Rho cycle](/_static/images/rho.png)

Advanced collision-finding techniques work by first detecting the start of the cycle and then finding the collision, without storing numerous values in memory and without needing to sort a long list.

## Cracking hashes

Having the hash value of something, and wanting to calculate the data it came from, in general, there is no unique solution. For short objects like passwords, there is. If someone uses an MD5 function to obscure a password (done by some old web applications still existing in the wild), then you can reverse it by guessing passwords until finding a match. There is no mathematical way to undo a hash function, so the best way is to make (or use) a library. 

## Windows passwords

The hash used by, for example, Windows Server is the NT Hash. If two users have the same password, they have exactly the same hash. 

The algorithm Microsoft uses takes the password and encodes in Unicode instead of ASCII, to allow for passwords in languages such as Chinese and Japanese that do not encode with 8-bits per character but 16-bits per character. Then it is run through MD4 (an algorithm even older than MD5) to produce the NT hash value.

Because password hashes have no variation and any two users with the same password will have the same hash, all the hackers that had cracked wordlists for the last decades have put their results on the internet. For example, you can use the [crackstation](https://crackstation.net/) or  [hashes.com](https://hashes.com/en/decrypt/hash). This availability has even resulted in a situation where you can just Google frequently used password hashes.

When the passwords cannot be cracked, you can try guessing using `hashlib`. Make series of guesses (or use a passwordlist), hash them, and hunt for the answer. 

```text
import hashlib

hashlib.new("md4", "password".encode("utf-16le")).hexdigest()
```

## Linux password hashes

In Linux, the hashes can be found in the `/etc/shadow` file.

```text
username:$6$ligE06T/QLQMANm9$8GDajwZJahwNnnW/OtfwLUGZHYcmTd9RByNz2e32iJAx37fSu7R1mpxTwWOqwlc4etyR/SLBkfiksitUHXRVV.:18961:0:99999:7:::
```

After each username comes `$6`, which indicates it is a type 6 password, then there is a random string of characters that goes up to the next dollar sign, the salt, and then an even longer random string of characters, which is the actual password hash itself.

When users have the same password, they have completely different hashes, because a random salt is added before hashing them, to obscure the fact that these passwords are the same.

Besides salting, stretching is also used. Calculating the hash uses 5,000 rounds of SHA-512, which takes much more CPU time. This might slow down attackers trying to make dictionaries of password hashes.

Make series of guesses (or use a wordlist for a dictionary attack), hash them, and hunt for an answer. 

```text
from passlib.hash import sha512_crypt

sha512_crypt.using(salt="ligE06T/QLQMANm9", rounds=5000).hash("password")
```

This will be very, very, time-consuming. You can also use Hashcat or John the Ripper.

## RootMe challenges

* [DCC Hash](../grounds/hashes/dcc.md)
* [DCC2 Hash](../grounds/hashes/dcc2.md)
* [LM Hash](../grounds/hashes/lm.md)
* [Message Digest 5](../grounds/hashes/md5.md)
* [NT Hash](../grounds/hashes/nt.md)
* [SHA-2 Hash](../grounds/hashes/sha2.md)
* [CISCO Salted password](../grounds/hashes/cisco.md)
* [SHA-3 Hash](../grounds/hashes/sha3.md)


## Security

Despite their apparent simplicity, hash functions can cause major security troubles when used at the wrong place or in the wrong way—for example, when weak checksum algorithms like CRCs are used instead of a crypto hash to check file integrity in applications transmitting data over a network. However, this weakness pales in comparison to some others, which can cause total compromise in seemingly secure hash functions.

## Resources

* [Collisions of MD5](https://repository.root-me.org/Cryptographie/EN%20-%20Collisions%20of%20MD5.pdf)
* [rfc1321](https://repository.root-me.org/RFC/EN%20-%20rfc1321.txt)