# Web cache poisoning

Web cache poisoning uses a variety of methods to sneak modified (usually malicious) data into a web cache and have it returned to a client instead of legitimate cached content. 

Modifying cache content is not an attack in itself but just a technique for delivering payloads, making web cache poisoning as dangerous as the underlying vulnerability that is targeted. While not easy to do, it can also be hard to detect and troubleshoot, making it an interesting tool for attackers and an important point for penetration testing and bug hunting.

## Steps

1. Check what kind of caching is used and detect web cache hits and misses. 
2. Identify and evaluate unkeyed inputs.
3. Web cache poisoning attacks are only possible when these inputs can be used to generate other responses dynamically or if the server reflects this input in its response without adequate validation or input sanitation. understand how the web server processes the unkeyed input to elicit a malicious response from the back-end server successfully.
4. Get the response cached: The success of a web caching attack depends on the successful storage of the harmful response in cache memory. Use trial & error to examine the behaviour of the cache. 

## Unkeyed inputs

* Reflected unkeyed headers: If the application directly reflects the value of an unkeyed header in the response, it opens the door to cache poisoning. Its value is not part of the cache key. If the attacker sends a request where only this header is maliciously modified, the response to this request will be cached, with the malicious payload targeting, for example, an XSS vulnerability. Users subsequently requesting content that matches the same cache key will receive the malicious version from the cache.
* Unkeyed port: If the port is not part of the cache key, it may be possible to perform a denial of service (DoS) attack by poisoning the cache with an inaccessible port number. If an attacker sends a request that includes such a port number and the error response is cached, users requesting the same URL without the port will immediately get the cached error instead of the expected page content. This will render the page inaccessible to users. 
* Unkeyed request method: Sometimes the HTTP request method (GET, POST, PUT, etc.) is not be part of the cache key. If the application is also vulnerable to parameter pollution, it may be possible to send a `POST` request containing a malicious payload that modifies a parameter for an XSS attack. The poisoned response will then be cached and because the cache key does not account for the HTTP method, it will be delivered to clients that send a normal GET request matching the same cache key.
* Unkeyed query string: If the query string of a request is unkeyed and reflected in the response, it may be possible to inject a malicious payload into a query parameter and cache the response. Clients sending a matching request with no query string would then receive the poisoned response. Because the attack is a typical script injection, it effectively turns a reflected XSS into a stored XSS, with the script stored in the web cache. If used directly, it is not hard to detect, but it may evade detection in more complex scenarios.

## Fat GET requests

If an application accepts non-standard GET requests that have a body (making them fat) and the request body is unkeyed **and** reflected in the response, it may be possible to include a malicious payload in the GET request, and the response will be cached (because the request body is not part of the key). Users sending a regular GET request that matches the same cache key will receive the poisoned response. In some cases, it may also be possible to use the `X-HTTP-Method-Override` header to trick the application into treating a fat `GET` request as a normal `POST` request.

## Cache busting

A cache-buster is a unique piece of code that prevents a browser from reusing an element it has already seen and cached, or saved, to a temporary memory file. 

    GET /?parameter1=whatever&parameter2=evil HTTP/1.1

A cache-buster doesn't stop a browser from caching an element, it just prevents it from reusing it.

For dual caches, Burp's `param miner` can add a dynamic cache buster to each request made, which can be helpful for bypassing one cache and focusing on the other.

## Escalation

The impact of web cache poisoning is heavily dependent on several key factors: What can successfully get cached, the amount of traffic on the affected page, and for more targeted attacks, who is likely to visit the poisoned page.

## Portswigger lab writeups

* [Web cache poisoning with an unkeyed header](../burp/cache/1.md)
* [Web cache poisoning with an unkeyed cookie](../burp/cache/2.md)
* [Web cache poisoning with multiple headers](../burp/cache/3.md)
* [Targeted web cache poisoning using an unknown header](../burp/cache/4.md)
* [Web cache poisoning via an unkeyed query string](../burp/cache/5.md)
* [Web cache poisoning via an unkeyed query parameter](../burp/cache/6.md)
* [Parameter cloaking](../burp/cache/7.md)
* [Web cache poisoning via a fat GET request](../burp/cache/8.md)
* [URL normalization](../burp/cache/9.md)
* [Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria](../burp/cache/10.md)
* [Combining web cache poisoning vulnerabilities](../burp/cache/11.md)
* [Cache key injection](../burp/cache/12.md)
* [Internal cache poisoning](../burp/cache/13.md)

## Remediation

Cache poisoning is just another vehicle for attackers to deliver their payloads. When hit by a cache poisoning attempt that injects an [XSS](xss.md) payload into the cache, it will be harmless if the application is not vulnerable to that type of cross-site scripting. Use [secure coding practices](https://devsecops.tymyrddin.dev/docs/notes/coding) at every stage of the development and operations pipeline.

Still, to minimise attackers using the web cache poisoning vehicle, these are some recommendations for configuring the web server cache:

* If the application only uses default ports, strip the port number from the `Host` header before generating the cache key. Poisoning via an unkeyed port value can lead to DoS.
* Caching only `GET` and `HEAD` requests reduces the risk of poisoning via an unkeyed request method. `POST` and other `HTTP` commands are designed to trigger an operation on the server, and responses to state-changing requests are often unique, hence there is no performance benefit to caching their responses anyway.
* Reject non-standard `GET` requests with a body (fat `GET` requests). Even better, do not have an application send such requests.
* As a first step for cache poisoning, attackers try to figure out what kind of caching is used and look at web cache hits and misses. Removing caching-specific headers as part of a defence-in-depth strategy can make such information gathering much more difficult. Note: Disabling these headers might come at a cost for client-side caching in the browser.

## Resources

* [Portswigger: Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [Portswigger: Bypassing Web Cache Poisoning Countermeasures](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures)
* [Snyk: Cache poisoning in popular open source packages](https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/)
* [Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/)
