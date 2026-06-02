# Hash length extension attack

[RootMe challenge: Service - Hash length extension attack](https://www.root-me.org/en/Challenges/Cryptanalysis/Service-Hash-length-extension-attack): H(key ∥ message)

You can use [Stephen Bradshaw's hlextend module](https://github.com/stephenbradshaw/hlextend).

## Resources

* [Everything-you-need-to-know-about-hash-length-extension-attacks (blog.skullsecurity.org)](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

## Counter moves

A length-extension attack abuses naive MAC-by-hash constructions. HMAC, rather than hash-of-secret-and-message, is the fix. The defender's view is in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
