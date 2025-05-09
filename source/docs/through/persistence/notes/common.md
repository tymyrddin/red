# Exploiting vulnerabilities

* Malware, more specifically ransomware, continues to be a significant threat. We are talking exploits.
* Supply chain attacks are relatively new but continue to grow in size and frequency.
* Cloud-based threats encompass a wide range of TTPs. And with so many businesses using the cloud, and cloud networks and the offered services becoming more intricate, their infrastructure has become "low-hanging fruit".
* Social engineering: phishing, spear phishing, whaling, smishing, vishing, baiting, piggybacking/tailgating, ...
* Insider threats.
* Mobile devices: many more infiltration opportunities than ever before.
* Each cybersecurity threat is a learning opportunity, but most organisations do not have an incident strategy and incident response team. And there may be incidents that were not noticed, and have been ungoing for a loooong time already ...

## Social engineering

Social engineering is the use of deception to try to trick a user into compromising system security through an email message, a text message, a phone call, etc. Social engineering attacks are a common way to test the effectiveness of a company’s security education program. 

## Application-based

### Injection attacks

Injection attacks are one of the most common types of attacks against applications today. Web applications are especially vulnerable because they are internet-facing and their audience is extended out to the Internet.

### Authentication attacks

Authentication attacks are methods that can be used to try to bypass the authentication or compromise
the security of the application by cracking the application’s passwords.

### Authorisation attacks

After a user authenticates to an application or API, the user is then authorised to perform different actions while using the application or API. A vulnerable application may not have authorisation configured properly and simply allows users and other applications to perform any task within the application.

### XSS and CSRF/XSRF attacks

Cross-site scripting, or XSS for short, is one of the most common vulnerabilities found in web applications and involves the hacker injecting client-side script into a web page that is then viewed and executed by others at a later time.

The goal of a CSRF/ XSRF attack is to get an unsuspecting user to submit data to a website the user has already logged on to. A CSRF/XSRF attack leverages the fact that the site has already authenticated the user to the site, and therefore trusts all actions from the user.

### Network-based vulnerabilities

Exploits that are created to leverage network-based vulnerabilities are interesting exploits because the attacks are performed across the network — an adversary does not need local access to the systems.

Network-based vulnerabilities can lead to compromise of the target operating system, privilege escalation, or loss or degradation of service performance. Most network-based vulnerabilities can be identified withvulnerability assessment, or by vulnerability research. The Metasploit Framework or SearchSploit can be used to validate public exploits for vulnerabilities identified during a vulnerability assessment.

Common public exploits are Name-resolution exploits; Link-Local Multicast Name Resolution (LLMNR)/NetBIOS Name Service(NBT-NS) poisoning; New Technology LAN Manager (NTLM) relay attacks; SMB exploits; SNMP exploits; SMTP exploits; to name but a few.

### Local host vulnerabilities

Systems today are a variety of devices, and each type of device comes with its own list of vulnerabilities: Operating system vulnerabilities; Unsecure service and protocol configurations; Privilege escalation vulnerabilities; Default account settings; Sandbox escape possibilities; and Physical device security vulnerabilities.
