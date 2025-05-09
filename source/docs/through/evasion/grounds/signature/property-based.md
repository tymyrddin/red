# Static property-based signatures

Signatures can be attached to several file properties, including file hash, entropy, author, name, or other 
identifiable information to be used individually or in conjunction. These properties are often used in rule sets 
such as YARA or Sigma.

Some properties may be easily manipulated, while others can be more difficult, specifically when dealing with 
pre-compiled closed-source applications.

## File Hashes

A file hash, also known as a checksum, is used to tag/identify a unique file. They are commonly used to verify a 
file's authenticity or its known purpose (malicious or not). File hashes are generally arbitrary to modify and are 
changed due to any modification to the file.

With access to the source for an application, any arbitrary section of the code can be modified and re-compiled to 
create a new hash. When dealing with a signed or closed-source application, bit-flipping can be used. Bit-flipping is 
a common cryptographic attack that will mutate a given application by flipping and testing each possible bit until 
it finds a viable bit. By flipping one viable bit, it will change the signature and hash of the application while 
maintaining all functionality.

A python script to create a bit-flipped list by flipping each bit and creating a new mutated variant (~3000 - 200000 
variants):

```text
import sys

orig = list(open(sys.argv[1], "rb").read())

i = 0
while i < len(orig):
	current = list(orig)
	current[i] = chr(ord(current[i]) ^ 0xde)
	path = "%d.exe" % i
	
	output = "".join(str(e) for e in current)
	open(path, "wb").write(output)
	i += 1
	
print("done")
```

Then search for intact unique properties of the file. For example, when bit-flipping `msbuild`, use 
[signtool](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) to search for a file with useable 
certificate. This will guarantee that the functionality of the file is not broken, and the application will maintain 
its signed attribution.

To leverage a script to loop through the bit-flipped list and verify functional variants:

```text
FOR /L %%A IN (1,1,10000) DO (
	signtool verify /v /a flipped\\%%A.exe
)
```

## Entropy

Entropy can be defined as _"the randomness of the data in a file used to determine whether a file contains hidden data 
or suspicious scripts."_ EDRs and other scanners often leverage entropy to identify potential suspicious files 
or contribute to an overall malicious score.

Entropy can be "too high" for obfuscated scripts, specifically when obscuring identifiable information such as 
variables or functions. Depending on the EDR employed, a “suspicious” entropy value is ~ greater than 6.8.

To lower entropy, replace random identifiers with randomly selected English words. For example, change a variable from 
`q234uf` to `nature`. To prove the efficacy of changing identifiers, observe how the entropy changes using 
[CyberChef](https://gchq.github.io/CyberChef/#recipe=Entropy('Shannon%20scale')).

## Resources

* [An Empirical Assessment of Endpoint Detection and Response Systems against Advanced Persistent Threats Attack Vectors](https://www.mdpi.com/2624-800X/1/3/21/htm)