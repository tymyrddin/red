# Static and dynamic analysis

While static analysis works for the common malware, dynamic analysis is needed for the more sophisticated and 
advanced kind of malware.

## Static

Static malware analysis involves examining any given malware sample without actually running or executing the code. 

This is usually done by determining the signature of the malware binary; the signature is a unique identification for 
the binary file. Calculating the cryptographic hash of the binary file and understanding each of its components helps 
determine its [signature](signatures.md). The executable of the malware binary file is loaded into a disassembler (for example, IDA) 
and the machine-executable code is converted to assembly language code. 

Different techniques can be used, like file fingerprinting, virus scanning, memory dumping, packer detection, 
and debugging.

## Dynamic

Dynamic malware analysis involves running the code in a controlled environment. The malware is run in a closed, 
isolated virtual environment and then its behaviour studied. The intention is to understand its functioning and 
behaviour and use this knowledge to stop its spread or to remove the infection. 

Debuggers are used to determine the functionality of the malware executable. 

## Resources

* [Hashtab Alternatives & Feature Highlights 2022](https://implbits.com/hashtab)
