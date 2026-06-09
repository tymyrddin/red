# Malware signatures

Depending on its variant, malware is largely obtrusive - in the sense that it leaves quite an extensive papertrail of 
evidence ...

The general process of a malware attack can be broken down into a few broad steps, which will generate data:

* Delivery: his could be of many methods, for example, USB (Stuxnet) or PDF attachments through "Phishing" campaigns.
* Execution: What does it do? If it encrypts files and leaves a ransom note, it is Ransomware. If it records keystrokes 
it is a Keylogger. If it collects personal preferences to display adware, it is Spyware. This stage can only be 
understood through analysing the sample.
* Maintaining persistence (not always the case!)
* Propagation (not always!)

There are two categories of fingerprints that malware may leave behind on a Host after an attack:

* `Host-Based Signatures` are the results of execution and any persistence performed by a Malware. For example, has a 
file been encrypted? Has any additional software been installed? These are two of many host-based signatures that are 
useful to know to prevent and check against further infection.
* `Network-Based Signatures` are the observations of any networking communication taking place during delivery, 
execution and propagation. For example, in Ransomware, the Malware contacted which wallet for Bitcoin payments?
Or for example, a large amount of "Samba" Protocol communication attempts may be an indication of WannaCry infection 
because of its use of "Eternalblue".