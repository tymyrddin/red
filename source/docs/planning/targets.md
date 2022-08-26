# Additional target considerations

Some considerations to keep in mind when performing the pentest on the
identified targets:

* Allow list (whitelisted) versus deny list (blacklisted): You
can ask to have your system added to the allow list by security controls.
* Security exceptions: You can ask your IP address or account to be added to 
security exceptions within security controls so that you are not blocked.
* IPS/WAF whitelist: Your IP address can be added to the whitelist on
the intrusion prevention system (IPS) and the web application firewall (WAF)
so that it is not blocked and you can test the web application.
* NAC: The customer may have network access control (NAC) features implemented that only allow 
devices in a secure state to connect to the network. This could affect your capabilities to 
connect to the network and perform the pentest. You may have to be placed on an exception list 
so that you can access the network from your pentest system.
* Certificate pinning: Certificate pinning refers to the process of associating a
host with the expected server it will receive certificates from. If the certificate
comes from a different system, the communication session will not occur. You
may need to disable certificate pinning on the network to allow
communication.
* Review the company security policy to
determine if there are any policies in place that would put limits on the actions
you can take.
* TBe aware of any technical constraints that may limit
your capabilities to perform the penetration test. There may be
firewalls blocking your scans during discovery of targets or there may be
network segments controlling communication.
* When performing the pentest, it is important to be aware of any differences in the environment, 
as any differences could change how the pentest tools respond. Be aware of export
restrictions when it comes to crossing borders with any encrypted content
and any other local and national government restrictions that may be in place
with regard to encryption and penetration testing tools. When performing a
pentest on large global companies, know that the laws are different in these
different companies with regard to using tools. Also, review any
corporate policies so that you are aware of the pentesting rules.
* Special scoping considerations: There may be other special scoping
considerations that may arise during the pre-engagement phase, such as
premerger testing and supply chain testing considerations. 