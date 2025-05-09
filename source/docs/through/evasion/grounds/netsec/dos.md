# Evasion via tactical DoS

Evasion via tactical DoS includes:

* Launching denial of service against the IDS/IPS
* Launching denial of Service against the logging server

An IDS/IPS requires more processing power as the number of rules grows and the network traffic volume increases. 
Especially in the case of IDS, the primary response is logging traffic information matching the signature. 
As a result, you might find it beneficial if you can:

* Create a huge amount of benign traffic that would simply overload the processing capacity of the IDS/IPS.
* Create a massive amount of not-malicious traffic that would still make it to the logs. This action would congest 
the communication channel with the logging server or exceed its disk writing capacity.

It is also worth noting that the target can be the IDS operator. By causing a vast number of false positives, you 
can try to cause "operator fatigue". Erm. That is ruthless. APT attackers are that, ruthless.