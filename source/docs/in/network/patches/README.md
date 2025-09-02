# Mycelium patches (routing protocols)

*A fungal network nourishing a single forest grove: intricate, local, and fiercely protected.*

Inside a single company or ISP, routers use protocols like OSPF or EIGRP to keep track of the best paths, almost like 
how you might memorize the quickest way to your local grocery store. These protocols update automatically if a link 
goes down, ensuring traffic takes the next best route without humans needing to intervene.

## The hidden challenges

When deploying routing protocols in an intranet, several hidden security challenges can arise, often overlooked during 
initial setup. These vulnerabilities can lead to unauthorised access, route manipulation, denial-of-service (DoS) 
attacks, and data interception. And even in intranets, misconfigured BGP can leak internal routes to the internet.

## Why this matters

Routing protocols are the hidden hyphae of your Mycelium Patch—if rot takes hold, spore-thieves can drain your 
nectar, strangle fruiting bodies, or twist the whole web into a strangler’s knot. Here’s why decay spreads unseen:

* [Routing Information Protocol](rip.md)
* [Enhanced Interior Gateway Routing Protocol](eigrp.md)
* [Open Shortest Path First](ospf.md)
* [Intermediate System to Intermediate System](is-is.md)
* [Border Gateway Protocol](bgp.md)
* [Static Routing](static.md)
* [First-Hop Redundancy Protocols](fhrp.md)

