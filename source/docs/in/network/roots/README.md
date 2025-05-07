# Rootways of the World Tree (attack trees)

*Vast, ancient roots intertwining beneath continents—essential for life, but vulnerable where they surface.*

When data needs to leave one network and enter another, like when you load a website hosted halfway across the world,
things get more complicated. This is where BGP (Border Gateway Protocol) comes in. Unlike the neighborhood routes, 
BGP isn’t about finding the shortest path. It is about finding the most acceptable one.

* BGP works like a postal service where each network announces: "Hey, I know how to reach these addresses!"
* Other networks then decide whether to trust that announcement based on business relationships (like paid transit deals or mutual "peering" agreements).
* Because BGP runs over TCP (the same protocol that powers web browsing and emails), these route updates are delivered safely, even over unstable connections.

## The hidden challenges

BGP was not designed with strong security in mind, so sometimes mistakes (or malicious attacks) can cause traffic to 
take wrong turns. There have been cases where huge chunks of the Internet were briefly "hijacked" because of a 
misconfigured BGP announcement. Tools like RPKI (a kind of cryptographic ID check for routes) are slowly making this 
harder to exploit, but the system still relies heavily on trust.

## Why this matters

Every time you send a message, stream a video, or load a webpage, this invisible dance of protocols is happening in 
the background. BGP stitches together the Internet’s fragmented networks, while the underlying tech (TCP, IP, and 
error-checking systems like ICMP) keeps the whole thing running smoothly. 

It is not perfect. Below are the attack trees on some of the various components that hold the digital world together:

* [Transmission Control Protocol](tcp.md)
* [Internet Protocol](ip.md)
* [Border Gateway Protocol](bgp.md)
* [BGPsec validation](bgpsec.md)
* [Internet Control Message Protocol](icmp.md)
* [Domain Name System](dns.md)
* [TLS/SSL (for BGPsec)](tls-ssl.md)
* [TCP-AO (Authentication Option)](tcp-ao.md)
* [MD5 (for TCP-AO)](md5.md)
* [Resource Public Key Infrastructure](rpki.md)

