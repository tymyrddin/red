# Scoping

## Initial meeting 
Have an initial meeting with the customer to discuss the scope of the project and get an
understanding of what their goals are for the penetration test. 

* What is the purpose of the penetration test? Why do they want one done?
* Are the systems to test internal systems, external systems, or both?
* What are the IP ranges of the systems that require testing?
* What are the domain names of the systems to be tested?
* Does the organisation own the systems using those IP addresses?
* Are there any systems hosted by third-party companies such as an ISP or a cloud provider?
* What applications and services need to be tested?
* Is testing the physical security controls in scope of the pentest?
* What types of tests are to be included? Are physical security or social engineering to be included? Are DoS attacks 
allowed?
* What user accounts are in scope for password cracking? Are we allowed to attempt to 
compromise administrative accounts?

With an unknown-environment (black box) test, the pentester is typically responsible for discovering target
services, and in some cases even the target IP addresses. If so, you run the risk of performing the test on an 
unauthorised IP address or system owned by someone else.

Even with a black box test you want the customer to give you the target IP addresses and
domain names so that you can be sure you have proper authorisations. 

## List the in-scope assets

* What wireless SSIDs are to be targeted?
* Internet Protocol (IP) range?
* Internal and external domain names to be targeted?
* APIs that are to be included? Stand-alone APIs such as custom DLLs? Web APIs such as RESTful web services?
* Physical locations that are in scope with the penetration test and that we do have permission for to try to bypass 
physical access controls to gain access to those locations?
* Domain name system (DNS) addresses used for internal DNS and external DNS?
* Which and what internal targets (on the LAN) and what external targets (on the Internet) are in scope?
* Assets that exist on-premises (first-party) and assets that are hosted in the cloud (third-party)?

You must get a separate permission from the third party or cloud provider to perform testing on those assets.

## More questions

Depending on the type of testing being performed, there are more questions you can ask during the scoping of the 
project. The Penetration Testing Execution Standard (PTES) website has an 
[extensive list of questions](http://www.pentest-standard.org/index.php/Pre-engagement#General_Questions) you can ask.
