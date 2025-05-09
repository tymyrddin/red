# Brute force

A brute force attack is a golden oldie, today still widely used and remains highly effective. Attackers use brute force attacks to:

* Crack passwords
* Decrypt encrypted data
* Gain access to unauthorised systems, websites or networks

For example, public and private keys are used for encrypting and decrypting the data in a cryptographic system. In a brute force attack, possible private keys are used to decipher an encrypted message or data. The algorithm must be known, and is usually found as open-source programs.

## Types of attacks

* In a **simple brute force attack**, an attacker tries to crack a small number of possible simple passwords or keys quickly. These attacks are only effective against systems with weak passwords or simple password policies. Simple passwords are guessed with common expressions like `password` and `p4ssw0rd!`.  These attacks can be done manually or use automation and scripts. Automated attacks are also more likely to be detected and blocked by security systems.
* In a **dictionary attack** an attacker tries different possible passwords with a pre-arranged list of words, typically taken from a dictionary, against a username. A program is used to try different combinations of words and phrases. Used are unabridged or special dictionaries, augmented with numbers and special characters, and dictionaries of passwords that have been leaked by earlier data breaches. These attacks can be effective in contexts where people choose passwords that are simply words or phrases.
* Rainbow tables are the precomputed tables containing the hash values used to crack passwords. In a **rainbow table attack** an attacker tries to crack hashes of passwords that have been hashed using a variety of hashing algorithms, including MD5, SHA-1, and NTLM. Attackers can quickly look up the corresponding plaintext for a given hash without executing the computationally intensive process of hashing all possible plaintexts and comparing the result with the target hash.
* In brute force attacks the attackers do not know the password. In a **reverse brute force attack** the attacker knows the PIN or password, and tries to find the matching username. Usually, an attacker uses passwords leaked by earlier data breaches that can be found and/or bought online. 
* In a **hybrid brute force attack**, an attacker combines a dictionary attack with a traditional brute force attack. The attacker will use a set of random characters and a program to try a list of common words and phrases. It allows the attacker to try both common and less common password options.
* In a **credential stuffing attack** an attacker uses a stolen (or bought) list of username and password pairs against various sites. These attacks can go undetected for a long time, as legitimate login credentials are used.
* In a **password spraying attack** one common password is applied to many accounts. These attacks are often successful as many people use the same password for multiple accounts. 
* In a **brute force attack on RDP connections** an attacker tries to correctly guess the password to a remote desktop protocol (RDP) connection. If attackers can correctly guess the password, they can spread laterally throughout the network, injecting malware.

## Physical attack

Physical attacks can vary from blackmail to abduction. And are increasingly common, as James Lopps [Known Physical Bitcoin Attacks](https://github.com/jlopp/physical-bitcoin-attacks) repository attests to.

## Remediation

* Use strong, unique passwords that are not based on words or phrases in a dictionary.
* Enable multifactor authentication (MFA).
* Keep track of login activities, like the number of failed login attempts and the failed IP addresses of users and locations.
* Limit the number of login attempts made within a certain period and lock down the account after a certain number of login attempts.

## Resources

* [danielmiessler/SecLists/passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
* [How to Calculate Password Entropy?](https://generatepasswords.org/how-to-calculate-entropy/)
* [Let’s settle the password vs. passphrase debate once and for all](https://proton.me/blog/protonmail-com-blog-password-vs-passphrase)
* [Check if your data has been leaked](https://cybernews.com/personal-data-leak-check/)
