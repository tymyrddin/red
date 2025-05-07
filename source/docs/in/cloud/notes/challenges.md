# Challenges and problems

## Lack of transparency

Not-so-well-known cloud services often use third party data centers. Users may not know where the data is stored and what hardware or software configuration is used. Such a lack of transparency exposes data to security risks. The cloud service provider may even be gathering and selling sensitive data without the knowledge of the user. 

Well-known cloud service providers like AWS, Azure, GCP, etc. usually conduct in-house security audits, but these resources cannot be audited by a security auditor the client or user chooses. Nor can clients or users respond if those underlying resources are hacked. This has to be reported, and the CSP will get to it (hopefully).

## Resource sharing

Cloud services share resources across multiple accounts. This resource sharing can prove problematic, and not only during cloud penetration testing. Some service providers do not even use proper segmentation of the users. 

If an organisation has a compliancy requirement which states that all the other accounts sharing the resource and the cloud service provider should be PCI DSS compliant too, this can lead to complex cloud infrastructure implementations. And such complex scenarios can make cloud penetration testing hard to do.

## Policy restrictions

Each cloud service provider has its own policy regarding conducting cloud penetration testing. This policy defines the endpoints and types of tests that can be conducted. And some require an advance notice before testing. 

These differences in policies can be a challenge and also limits the scope of cloud penetration testing, while black hats have no such squirms.

### AWS

There are 8 permitted services for Amazon web services on which cloud pentesting can be performed without prior notice. Those are mentioned in the Permitted Services of the [Penetration Testing policy](https://aws.amazon.com/security/penetration-testing/). 

These are not permitted:

* Denial of Service (DOS) and Distributed Denial of Service Attacks (DDOS).
* DNS zone walking.
* Port, Protocol, or Request flooding attacks.

If you wish to perform a network stress test, there is a separate policy for that.

## Azure

Azure allows cloud pentesting on eight Microsoft products which are mentioned in its [Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement). 

These are not permitted:

* Cloud pentesting on other azure customers or data other than your own.
* DOS and DDoS attacks or tests which create a huge amount of traffic.
* Performing intensive network fuzzing attacks on Azure VMs
* Phishing or any other social engineering attacks against Microsoft employees.
* Violating Acceptable Use Policy.

## GCP

The Google Cloud Platform has no special cloud penetration testing policy, you just need to abide by their [Acceptable Use Policy](https://cloud.google.com/terms/aup) and [Terms of Service](https://cloud.google.com/terms/). There is no need to inform Google before testing. 

The Acceptable Use Policy does not permit:

* Piracy or any other illegal activity.
* Phishing.
* Spamming.
* Distributing trojans, ransomware, etc. during the tests.
* Violating the rights of other GCP users or conducting penetration tests on their assets.
* Violating or trying to circumvent terms of service.
* Interfering with the equipment supporting GCP.

## Resources

* [Cloud Native Security](https://www.fugue.co/cloud-security)