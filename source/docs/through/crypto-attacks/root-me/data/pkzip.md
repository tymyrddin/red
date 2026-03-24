# Protected PKZIP file

[RootMe: File - PKZIP](https://www.root-me.org/en/Challenges/Cryptanalysis/File-PKZIP?lang=en): A protected ZIP file, you have to find what’s inside.

## PKZIP

PKZIP encryption has been around since 1990, and its decryption is directly supported in most desktop environments (Windows, macOS, most Linux distros). This makes it one of very few options when recipients are not allowed to run any unknown program, and the most likely to allow smooth decryption by an unspecified legitimate receiver holding the password.

Even with a high-entropy password it can be very vulnerable when: 

* An adversary knows the start (sometime even part of) any file bundled in the archive.
* The archive contains many files.
* The archive was prepared with a tool using a poor entropy source, as many are.

In general, enough redundancy in the plaintext can allow a practical ciphertext-only attack for a poor cipher; and allows key enumeration for almost any cipher. Note, "there's almost no way to get it right unless you have the beginning of the file."

## Solution

Download the file using `wget` and use [fcrackzip](https://www.kali.org/tools/fcrackzip/)

```text
fcrackzip -c 1 -l 2-17 -u ch5.zip
```

## Resources

* [Cracking PKZIP file's password](https://repository.root-me.org/Cryptographie/EN%20-%20Cracking%20PKZIP%20file's%20password.pdf)

