# Application layer hacks

Hacking the layer of the OSI Model just beneath the surface of user interfaces, and on top of the other 6 layers of the model. In this layer, data is presented in a form that user-facing applications can use.

Most attacks nowadays are aimed at web applications, and web browsers are one of the favourite attack tools. Enough reasons to have a deeper look at application encryption attacks from the network perspective.

## Attacks against SSL

1. SSL stripping
   * Configure attack machine for IP forwarding
   * Route all HTTP traffic to SSLStrip
   * Run SSLStrip
2. SSL hijacking
3. SSL beast

### SSL stripping

SSL stripping downgrades an HTTPS connection to HTTP by intercepting the TLS authentication sent from the application to the user. The adversary sends an unencrypted version of the application’s site to the user while maintaining the secured session with the application. 

It does not do any magical stuff to fulfil the job, it just replaces the protocol of all HTTPS links in the sniffed traffic. The attacker must take care that the traffic of the victim flows over his host by launching some kind of on-path attack first.

Run `sslstrip` and write the results to a file (`-w strip.log`), listening on port 54321 (`-l 54321`):

    # sslstrip -w strip.log -l 54321

### SSL hijacking

In SSL hijacking an adversary forges authentication keys and passes those to both the user and application during a TCP handshake. This sets up what appears to user and application to be a secure connection while the man in the middle controls the entire session. 

### SSL beast

SSL beast is an attack developed by Juliano Rizzo and Thai Duong, which leverages weaknesses in cipher block chaining (CBC) to exploit the Secure Sockets Layer (SSL) protocol. The CBC vulnerability can enable man-in-the-middle (MITM) attacks against SSL in order to silently decrypt and obtain authentication tokens, providing hackers with access to the data passed between a Web server and the Web browser accessing the server.

## HTTPS spoofing

A forged certificate is sent to the target’s browser after the initial connection request to a secure site is made. It contains a digital thumbprint associated with the compromised application, which the browser verifies according to an existing list of trusted sites and because most browsers support the display of punycode hostnames in their address bar, it allows the adversary to access data entered by the victim before it is passed to the application. The browser shows that the website’s certificate is legitimate and secure, and users will not notice that it is a bogus version of the site they expect to visit.

In HTTPS session spoofing an adversary uses stolen or counterfeit session tokens to initiate a new session and impersonate the original user, who might not be aware of the attack. The difference between HTTPS session spoofing and HTTPS spoofing lies in the timing of the attack. Session hijacking is done against a user who is logged in and authenticated, so from the target's point of view the attack will most likely cause the application to behave unpredictably or crash.

1. Homograph attack
   * Register a domain name that is similar (using punycode for example) to the domain name of the target website (AND)
   * Register its SSL certificate to make it look legitimate and secure
2. Social engineering
   * Send a link to the intended victim
   * ...

## Resources

* [Phishing with Unicode Domains](https://www.xudongz.com/blog/2017/idn-phishing/), Xudong Zheng, April 14, 2017


