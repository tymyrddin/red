# RSA Decipher oracle

[RootMe Challenge: Darkness cannot drive out darkness; only light can do that](https://www.root-me.org/en/Challenges/Cryptanalysis/RSA-Decipher-Oracle): You have sucessfully intercepted a `C` text, encrypted with a RSA keypair which you know the `(n, e)` public component.

Luckily, your victim has made a mistake by using a server that allows you to decrypt any ciphered text with his public key, except for those including a secret that must stay encrypted.

Your job is to handle it in order to decrypt this weird message!

```text
n = 456378902858290907415273676326459758501863587455889046415299414290812776158851091008643992243505529957417209835882169153356466939122622249355759661863573516345589069208441886191855002128064647429111920432377907516007825359999
e = 65537
c = 41662410494900335978865720133929900027297481493143223026704112339997247425350599249812554512606167456298217619549359408254657263874918458518753744624966096201608819511858664268685529336163181156329400702800322067190861310616
```

![RSA Oracle](/_static/images/oracle1.png)

1. Calculate the ciphertext
2. Encrypt a message
3. Enter the resulting ciphertext to be decrypted

![RSA Oracle](/_static/images/oracle2.png)

4. Copy the resulting plaintext and use it to decrypt $n$

## Resources

* [Chosen ciphertext attacks against protocols based on the RSA encryption standard - Daniel Bleichenbacher](https://repository.root-me.org/Cryptographie/Asym%C3%A9trique/EN%20-%20Chosen%20ciphertext%20attacks%20against%20protocols%20based%20on%20the%20RSA%20encryption%20standard%20-%20Daniel%20Bleichenbacher.pdf)
* [A new and optimal chosen-message attack on RSA-type cryptosystems](https://repository.root-me.org/Cryptographie/Asym%C3%A9trique/EN%20-%20A%20new%20and%20optimal%20chosen-message%20attack%20on%20RSA-type%20cryptosystems.pdf)
