# Rules of engagement

The “rules of engagement” refer to any restrictions and details in regard to
how the customer wants the penetration test performed.

* The timeline for the penetration test for each task and phase being performed.
* When testing is to be performed.
* Types of allowed and disallowed tests.
* What to test (locations, targets, services, accounts, and applications).
* How the results should be reported and method of communication of the pentest details and results. 
* Who the organisational liaison of the red team is. Set up a secure communication channel so that all communications are encrypted.
* How frequently updates are to be communicated.
* A signed authorisation to perform the pentesting.
* Legal considerations with third parties, verify that you have authorisation from the third party.
* Discuss security controls that could shun and slow down the pentest (security controls such as
firewalls, intrusion prevention systems, and blacklisting on the network). If network is not in scope, such limitations do not make sense.
* Discuss whether the effectiveness of the security controls in place are in scope. Was the company security team able to detect
and respond to information gathering, footprinting attempts, scanning and enumeration, and attacks on systems?
* It is important to know why the pentest is being performed, but also who it is
being performed for. The report will need to be written to satisfy the goals of the pentest and be written to include 
information for the intended audience.

## Importance of liaison

Another reason to communicate with the customer is to let the customer know if something unexpected arises while doing 
the pentest, such as if a critical vulnerability is found on a system, a new target system is found that is outside 
the scope of the penetration test targets, or a security breach is discovered when doing the penetration test. 
You will need to discuss how to handle such discoveries and who to contact if those events occur. In case of such 
events, stop the pentesting temporarily to discuss the issue, then resume once a resolution has been determined.

## Support resources

Support resources to ask from the customer:

* WSDL/WADL files, XML-based files that describe the web service.
* SOAP project file to view details about the functionality of a web service.
* SDK documentation to get a better understanding of the functionality provided by the SDK and types of calls that can 
be made by applications.
* Swagger document, describing the functionality of an application programming interface (API). 
* XSD, an XML schema document used to describe the structure of an XML document and is a great tool to help understand 
the data stored in XML.
* Sample application request messages sent to an application to obtain detailed information about the
structure of the request.
* Architectural diagrams of the application and all of its components.

## Budget
A big part of the pre-engagement activities is determining the cost of the pentest. Once you have an idea of the 
size of the organisation and the target resources for the penetration test, you can estimate the cost of the
pentest based on the hours you expect it to take and the cost per hour. Add 20 percent additional time to the 
estimated hours to accommodate any incidents that may slow down the penetration test. If that doesn't happen 
you can always lower the price afterwards.