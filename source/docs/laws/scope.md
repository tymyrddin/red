# Scope and objectives

The key to a successful engagement is clearly defined client objectives. These should be discussed between the 
client and red team to create a mutual understanding between both parties of what is expected and provided. 
Objectives are the basis for the rest of the engagement documentation and planning.

Engagements can be categorised in general internal/network testing or focused adversary emulation. 
* A focused adversary emulation will define a specific APT or group to emulate. This can be determined based on 
groups that target the organisation's particular industries, for example, finance institutions and APT38. 
* An internal or network penetration test will follow a similar structure but will often be less focused and use more 
standard TTPs. 

## Scope

The next keystone to a precise and transparent engagement is a well-defined scope. The scope will vary by organisation 
and what their infrastructure and posture look like. As with pentesting, a client's scope will typically define what 
you cannot do or target; it can also include what you can do or target.

While client objectives can be discussed and determined along with the providing team, a scope should only be set 
by the client. In some cases the red team may discuss a grievance of the scope if it affects an engagement. They 
should have a clear understanding of their network and the implications of an assessment. The specifics of the 
scope and the wording will always look different

An example of what a client's scope may look like:

* No exfiltration of data.
* Production servers are off-limits.
* 10.0.3.8/18 is out of scope.
* 10.0.0.8/20 is in scope.
* System downtime is not permitted under any circumstances.
* Exfiltration of PII is prohibited.

When analysing objectives or scopes from a red team perspective, it is essential to understand the more profound 
meaning and implications. Always have a dynamic understanding of how the team would approach the problems/objectives. 
If needed, start engagement plans from only a bare reading of the client objectives and scope.