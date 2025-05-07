# Account and privilege attacks

Compromising API-based credentials: For AWS, this can be SSH keys, access keys, and secrets. For Azure, this can be credentials, keys, or certificates. Google even offers custom authentication methods.

Credentials are stored somewhere. They may not be stored securely, and can end up in places
where they should not be. When compromised, misconfigurations in identity and access management (IAM) schemes can lead to privilege escalation or account takeover for gaining full administrative access to a cloud account.

## Credential harvesting

Credential harvesting is one of the primary attack vectors for cloud environments. There are different approaches, but one of the most common is to mine source code repositories.

### Federated authentication

Federated authentication is becoming more common. It uses Security Assertion Markup Language (SAML) and takes organisational authentication to create an authentication token for the cloud service. This token can then be decrypted and assessed for authentication information by the cloud provider. The information shared from the organisation is part of a signed SAML assertion. With federated authentication, corporate credentials become very valuable and spraying attacks can get an attacker some level of access within an organisation to make privilege escalation, phishing, and other attacks easier.

## Account takeover

Account takeover is gaining pervasive access to an account: the attacker has privileges that are equivalent to the account owner. Usually as the result of spear phishing, misconfigured access, or privilege escalation from domain privileges into the cloud. This may go beyond the cloud account itself and into federated applications, cloud assets, hosted data, and network boundaries.

### Attack

Grant persistent access within the environment, resulting in pervasive access to data and commands
    
1. Attacking OAuth and federation (SolarWinds)
2. Create permissive policies that look benign
3. Add certificates or access keys to a user controlled by an attacker
4. Add persistence to applications that have elevated privileges within the account
5. Assign malicious policies to users or systems
6. Add permissions to existing policies

## Password spraying

In many cases, multifactor authentication will be in place and will mitigate these attacks, and in case vulnerable cloud interfaces are exposed, password spraying tools designed for common login services may not work. Use cloudspecific tools for password spraying.

## Remediation

Using common or weak passwords can make cloud accounts vulnerable to brute force attacks. The attacker can use automated tools to make guesses thereby making way into the account using those credentials. The results can lead to a complete account takeover. 

* Reusing passwords.
* Using easily rememberable passwords.

## Resources

* [SAML assertions](http://saml.xml.org/assertions)
* [Undetected Azure Active Directory Brute-Force Attacks](https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks)
* [AWS Metadata service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
* [AWS Get access key info](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html)
* [SolarWinds breach 2020](https://www.bankinfosecurity.com/solarwinds-attackers-manipulated-oauth-app-certificates-a-16253)
* [Amazon Fraud Detector launches Account Takeover Insights (ATI)](https://aws.amazon.com/about-aws/whats-new/2022/07/amazon-fraud-detector-account-takeover-insights/)
