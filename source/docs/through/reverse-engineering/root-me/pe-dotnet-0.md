# PE x86 0 protection

[RootMe challenge: PE DotNet - 0 protection](https://www.root-me.org/en/Challenges/Cracking/PE-DotNet-0-protection): Managed code

Retrieve the password asked by this binary.

## Resources

* [Introduction to Cracking - (Part I)](https://www.go4expert.com/articles/introduction-cracking-part-i-t17368/)
* [Demystifying Dot NET reverse engineering, part 1: Big introduction](https://resources.infosecinstitute.com/topic/demystifying-dot-net-reverse-engineering-part-1-big-introduction/)

## Counter moves

.NET assemblies decompile almost to source without protection. Obfuscation and anti-tamper are the standard counters. Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
