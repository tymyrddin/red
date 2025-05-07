# Scope discovery

Gather deeper and wider

* Discover websites on the same server
* Discover subdomains
* Discover email addresses
* Discover sensitive files

## WHOIS and Reverse WHOIS

Use whois to gather Domain name, IP address, Administrative Details, autonomous system number, DNS

* Go to `www.arin.net/whois` and search for `target name` in the ARIN Whois/RDAP Search bar.
* Find a handle which displays more information about this registration including the range of IP addresses.
* Find an entry with a net range (public IPs).
* Determine all the public IP blocks the target may have.

If you cannot find any results try some other Whois database search sites.

## IP addresses

    nslookup www.target.com

Setting the type of query to MX (mail exchange) records:

```text
nslookup
set type=MX
target.com
```

Then use `nslookup` again to resolve the FQDNs of the mail servers to IP adressess.

Try a DNS zone transfer:

```text
nslookup
server <ip_or_fqdn_of_target_DNS_server>
set type=all
ls -d <target_domainname>
```

If successful, make a note of it and add it to the remediation list in the pentest report.

## Researching certificates

Another way of finding hosts is to take advantage of the Secure Sockets Layer(SSL) certificates used to encrypt web traffic. An SSL certificate’s `Subject Alternative Name` field lets certificate owners specify additional hostnames that use the same certificate, so you can find those hostnames by parsing this field. Use online databases like [crt.sh](https://crt.sh/), [Censys](https://censys.io/), and Cert Spotter to find certificates for a domain.

👉 Wildcard certificates are a single point of failure. If we stumble upon the private key while roaming the network, we could intercept the communication flow of ***all*** applications using that same parent domain.

When a certificate authority issues a certificate, these are entered into a central repository called a certificate log. This repository keeps a binary tree of all certificates, where each node is the hash of its child nodes, thereby guaranteeing the integrity of the entire chain. All issued TLS certificates should be publicly published to detect domain spoofing, typo-squatting, homograph attacks, and other mischievous ways to deceive and redirect users. These logs can be searched.

Secret applications with little security hiding behind proxies can be exposed, and minimally subdomain enumeration is way faster.

## Subdomain enumeration

After finding as many domains on the target as possible, locate as many subdomains on those domains as you can. Each subdomain represents a new angle for attacking the network. The best way to enumerate subdomains is to use automation. Tools like [Sublist3r](https://github.com/aboul3la/Sublist3r), [SubBrute](https://github.com/TheRook/subbrute), [Amass](https://github.com/OWASP/Amass/), and [Gobuster](https://github.com/OJ/gobuster) can enumerate subdomains automatically with a variety of wordlists and strategies. For example, Sublist3r works by querying search engines and online subdomain databases, while SubBrute is a brute-forcing tool that guesses possible subdomains until it finds real ones. Amass uses a combination of DNS zone transfers, certificate parsing, search engines, and subdomain databases to find subdomains. You can build a tool that combines the results of multiple tools to achieve the best results.

## Service Enumeration

Next, enumerate the services hosted on the machines you’ve found. Since services often run on default ports, a good way to find them is by port-scanning the machine with either active or passive scanning. 

In active scanning, you directly engage with the server. Active scanning tools send requests to connect to the target machine’s ports to look for open ones. You can use tools like [nmap](https://nmap.org/download.html) or [masscan](https://github.com/robertdavidgraham/masscan) for active scanning.

In passive scanning, third-party resources are in use to learn about a machine’s ports without interacting with the server. Passive scanning is stealthier and helps attackers avoid detection. To find services on a machine without actively scanning it, you can use [Shodan](https://www.shodan.io/dashboard), [Censys](https://censys.io/) and [Project Sonar](https://www.rapid7.com/research/project-sonar/). Combine the information gathered from different databases for the best results. 

## Enumerate webserver directories

The next thing you can do to discover more of the site’s attack surface is brute-force the directories of the web servers you’ve found. Finding directories on servers is valuable, because through them, you might discover hidden admin panels, configuration files, password files, outdated functionalities, database copies, and source code files. Directory brute-forcing can sometimes allow you to directly take over a server. Even if you can’t find any immediate exploits, directory information often tells you about the structure and technology of an application.

The `nmap` NSE script [http-enum.nse](https://nmap.org/nsedoc/scripts/http-enum.html) offers a quite extensive fingerprint, especially when including Nikto database, but there are no guarantees all will be seen. And Nikto is very noisy.

You can use [Dirsearch](https://github.com/maurosoria/dirsearch) or [Gobuster](https://github.com/OJ/gobuster) for directory brute-forcing. These tools use wordlists to construct URLs, and then request these URLs from a web server. If the server responds with a status code in the 200 range, the directory or file exists. This means you can browse to the page and see what

An example of running a Dirsearch command. The `-u` flag specifies the hostname, and the `-e` flag specifies the file extension to use when constructing URLs:

    ./dirsearch.py -u target_url -e php

Gobuster’s `dir` mode can be used to find additional content on a specific domain or subdomain. This includes hidden directories and files. In this mode, you can use the `-u` flag to specify the domain or subdomain you want to brute-force and `-w` to specify the wordlist you want to use:

    gobuster dir -u target_url -w wordlist

Manually visiting all the pages you’ve found through brute-forcing can be time-consuming. Instead, use a screenshot tool like [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness/) or [Snapper](https://github.com/dxa4481/Snapper/) to automatically verify that a page is hosted on each location. EyeWitness accepts a list of URLs and takes screenshots of each page. In a photo gallery app, you can quickly skim these to find the interesting-looking ones. Keep an eye out for hidden services, such as developer or admin panels, directory listing pages, analytics pages, and pages that look outdated and ill-maintained. These are all common places for vulnerabilities to manifest.

## Spidering the site

Another way of discovering directories and paths is through web spidering, or web crawling, a process used to identify all pages on a site. A web spider tool starts with a page to visit. It then identifies all the URLs embedded on the page and visits them. By recursively visiting all URLs found on all pages of a site, the web spider can uncover many hidden endpoints in an application.

OWASP Zed Attack Proxy (ZAP) has a built-in web spider, and Burp Suite has an equivalent tool called the crawler.

## Third-party hosting

Take a look at the company’s third-party hosting footprint. For example, look for the organisation’s S3 buckets. A way to find those is through Google dorking. 

    site:s3.amazonaws.com COMPANY_NAME
    site:amazonaws.com COMPANY_NAME

If the company uses custom URLs for its S3 buckets, try more flexible search terms instead. Companies often still place keywords like `aws` and `s3`in their custom bucket URLs:

    amazonaws s3 COMPANY_NAME
    amazonaws bucket COMPANY_NAME
    amazonaws COMPANY_NAME
    s3 COMPANY_NAME

Another way of finding buckets is to search a company’s public GitHub repositories for S3 URLs. Try searching these repositories for the term `s3`.

[GrayhatWarfare](https://buckets.grayhatwarfare.com/) is another online search engine you can use to find publicly exposed S3 buckets.

And you can try to brute-force buckets by using keywords. [Lazys3](https://github.com/nahamsec/lazys3/) is a useful tool for that. It relies on a wordlist to guess buckets that are permutations of common bucket names. [Bucket Stream](https://github.com/eth0izzle/bucket-stream/) parses certificates belonging to an organisation and finds S3 buckets based on permutations of the domain names found on the certificates. Bucket Stream also automatically checks whether the bucket is accessible.

Once you’ve found a couple of buckets that belong to the target organisation, use the AWS command line tool to see if you can access one. Install the tool with:

    pip install awscli

Then configure it to work with AWS by following Amazon’s [documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

Try listing the contents of buckets:

    aws s3 ls s3://BUCKET_NAME/

Try copying files to your local machine:

    aws s3 cp s3://BUCKET_NAME/FILE_NAME/path/to/local/directory

Try copying a local file named TEST_FILE into the target’s S3 bucket:

    aws s3 cp TEST_FILE s3://BUCKET_NAME/

Clean up:

    aws s3 rm s3://BUCKET_NAME/TEST_FILE

## GitHub Recon

Search an organisation’s GitHub repositories for sensitive data that has been accidentally committed, or information that could lead to the discovery of a vulnerability.

Start by finding the GitHub, GitLab, or Bitbucket usernames relevant to your target. You should be able to locate these by searching the organisation’s name or product names via the search bar, or by checking the accounts of known employees.

For each repository, pay special attention to Issues and Commits sections. These sections are full of potential info leaks: they could point attackers to unresolved bugs, problematic code, and the most recent code fixes and security patches. Recent code changes that haven’t stood the test of time are more likely to contain bugs. Look at any protection mechanisms implemented to see if you can bypass them. You can also search the Code section for potentially vulnerable code snippets. On GitHub, once you’ve found a file of interest, also check the Blame and History sections on the top-right corner of the file’s page to see how it was developed.

Check if any of the source code deals with important functions such as authentication, password reset, state-changing actions, or private info reads. Pay attention to code that deals with user input, such as HTTP request parameters, HTTP headers, HTTP request paths, database entries, file reads, and file uploads, because they provide potential entry points for attackers to exploit the application’s vulnerabilities. Look for any configuration files, as they allow you to gather more information about your infrastructure. Also, search for old endpoints and S3 bucket URLs that you can attack. Record these files for further review in the future.

Outdated dependencies and the unchecked use of dangerous functions are also a huge source of bugs. Pay attention to dependencies and imports being used and go through the versions list to see if they’re outdated. Record any outdated dependencies. You can use this information later to look for publicly disclosed vulnerabilities that would work on the target.

Tools like Gitrob and TruffleHog can automate the GitHub recon process. [Gitrob](https://github.com/michenriksen/gitrob/) locates potentially sensitive files pushed to public repositories on GitHub. [TruffleHog](https://github.com/trufflesecurity/truffleHog/) specializes in finding secrets in repositories by conducting regex searches and scanning for high-entropy strings.

