# Scanning cloud infrastructure

Most internet resources on cloud providers, like load balancers, content distribution networks, S3 buckets, 
etc., regularly rotate their IP addresses. If the nmap takes too long, the addresses will have 
been assigned to another customer and the results will no longer be relevant. Scan domain names, not IP addresses.

    nmap -F -sV -iL domains.txt -oA results

## Spotting hidden relationships

Consider the core business and what other servers and datastores there are likely to be.
Keep an eye open for information that might indicate where to find those.