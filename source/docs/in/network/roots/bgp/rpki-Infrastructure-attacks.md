# RPKI infrastructure attacks

## Attack pattern

The Resource Public Key Infrastructure (RPKI) was designed to secure Border Gateway Protocol (BGP) routing through cryptographic validation of route origins. However, the RPKI ecosystem itself introduces new attack vectors that target its distributed repository system, validation mechanisms, and protocol implementations. These attacks can compromise the integrity of the entire routing security framework, enabling sophisticated adversaries to manipulate RPKI data to facilitate BGP hijacking or cause widespread routing disruptions.

```text
1. RPKI infrastructure attacks [OR]

    1.1 Repository system attacks [OR]
    
        1.1.1 Publication point manipulation
            1.1.1.1 RPKI object deletion or modification
            1.1.1.2 Stale object substitution attacks
            1.1.1.3 Man-in-the-middle attacks on repository transfers
            
        1.1.2 Repository service exploitation
            1.1.2.1 RSYNC server vulnerabilities 
            1.1.2.2 RRDP (RPKI Repository Delta Protocol) implementation flaws
            1.1.2.3 Denial-of-service against repository servers
            
        1.1.3 Content delivery network attacks
            1.1.3.1 CDN cache poisoning for RPKI objects
            1.1.3.2 HTTPS interception and manipulation
            1.1.3.3 DNS spoofing for repository locations
            
    1.2 Cryptographic attack vectors [OR]
    
        1.2.1 Certificate authority compromise
            1.2.1.1 RIR root CA private key theft
            1.2.1.2 Intermediate CA exploitation
            1.2.1.3 Trust anchor manipulation
            
        1.2.2 Signature validation bypass
            1.2.2.1 Algorithm downgrade attacks
            1.2.2.2 Weak cryptographic implementation exploitation
            1.2.2.3 Signature verification logic flaws
            
        1.2.3 Key management attacks
            1.2.3.1 Hardware security module (HSM) vulnerabilities 
            1.2.3.2 Key generation weaknesses
            1.2.3.3 Certificate revocation list manipulation
            
    1.3 Validator targeting [OR]
    
        1.3.1 Relying party software exploitation
            1.3.1.1 Buffer overflow attacks 
            1.3.1.2 Memory corruption vulnerabilities
            1.3.1.3 Remote code execution flaws
            
        1.3.2 Cache poisoning attacks
            1.3.2.1 Validated ROA payload manipulation
            1.3.2.2 Trust chain compromise
            1.3.2.3 Stale data persistence exploitation
            
        1.3.3 Protocol implementation attacks
            1.3.3.1 RPKI-to-router protocol manipulation
            1.3.3.2 Serial number synchronisation attacks
            1.3.3.3 Error handling exploitation
            
    1.4 Network infrastructure attacks [OR]
    
        1.4.1 Transport layer targeting
            1.4.1.1 RSYNC protocol exploitation 
            1.4.1.2 HTTPS man-in-the-middle attacks
            1.4.1.3 TCP session hijacking
            
        1.4.2 Firewall and ACL bypass
            1.4.2.1 Protocol evasion techniques
            1.4.2.2 Port and service manipulation
            1.4.2.3 Tunnelling attacks
            
        1.4.3 DDoS and resource exhaustion
            1.4.3.1 Repository server flooding
            1.4.3.2 Validator resource exhaustion
            1.4.3.3 Network bandwidth saturation
            
    1.5 Data integrity attacks [OR]
    
        1.5.1 Manifest manipulation 
            1.5.1.1 Manifest forgery and replay attacks
            1.5.1.2 File hash manipulation
            1.5.1.3 Manifest expiration exploitation
            
        1.5.2 ROA manipulation
            1.5.2.1 Unauthorised ROA creation
            1.5.2.2 MaxLength attribute exploitation 
            1.5.2.3 Origin AS manipulation
            
        1.5.3 Object validation bypass
            1.5.3.1 Malformed object processing flaws
            1.5.3.2 Parser implementation vulnerabilities
            1.5.3.3 ASN.1 decoding exploits
            
    1.6 Configuration and management attacks [OR]
    
        1.6.1 Administrative interface targeting
            1.6.1.1 Web portal vulnerabilities
            1.6.1.2 API endpoint exploitation
            1.6.1.3 Credential theft and brute force attacks
            
        1.6.2 Human factor exploitation
            1.6.2.1 Social engineering attacks
            1.6.2.2 Configuration error induction 
            1.6.2.3 Operational procedure manipulation
            
        1.6.3 Backup and recovery targeting
            1.6.3.1 Backup system compromise
            1.6.3.2 Recovery process manipulation
            1.6.3.3 Archive integrity attacks
            
    1.7 Trust chain exploitation [OR]
    
        1.7.1 Trust anchor compromise
            1.7.1.1 TAL (trust anchor locator) manipulation
            1.7.1.2 Root certificate distribution attacks
            1.7.1.3 Trust propagation exploitation
            
        1.7.2 Certificate authority hierarchy attacks
            1.7.2.1 Intermediate CA compromise
            1.7.2.2 Certificate signing request manipulation
            1.7.2.3 Path validation bypass
            
        1.7.3 Revocation mechanism targeting
            1.7.3.1 CRL (certificate revocation list) manipulation
            1.7.3.2 OCSP stapling attacks
            1.7.3.3 Revocation status bypass
            
    1.8 Protocol-specific attacks [OR]
    
        1.8.1 RTR (RPKI-to-router) protocol attacks 
            1.8.1.1 Session hijacking and manipulation
            1.8.1.2 PDU (protocol data unit) forgery
            1.8.1.3 Serial number manipulation
            
        1.8.2 RRDP protocol exploitation
            1.8.2.1 Delta file manipulation
            1.8.2.2 Snapshot integrity attacks
            1.8.2.3 Session management vulnerabilities
            
        1.8.3 RSYNC protocol attacks 
            1.8.3.1 Authentication bypass
            1.8.3.2 File transfer manipulation
            1.8.3.3 Protocol option exploitation
            
    1.9 Supply chain attacks [OR]
    
        1.9.1 Software distribution compromise
            1.9.1.1 Validator software backdoors
            1.9.1.2 Update mechanism manipulation
            1.9.1.3 Dependency chain exploitation
            
        1.9.2 Hardware compromise
            1.9.2.1 HSM (hardware security module) vulnerabilities 
            1.9.2.2 Network device firmware manipulation
            1.9.2.3 Manufacturing process attacks
            
        1.9.3 Third-party service targeting
            1.9.3.1 Cloud service compromise
            1.9.3.2 CDN infrastructure attacks
            1.9.3.3 Hosted RPKI service exploitation 
            
    1.10 Advanced persistent threats [OR]
    
        1.10.1 State-sponsored attacks
            1.10.1.1 Long-term validator compromise
            1.10.1.2 Cryptographic backdoor insertion
            1.10.1.3 Infrastructure-wide targeting
            
        1.10.2 Organised crime targeting
            1.10.2.1 Ransomware attacks on RPKI infrastructure
            1.10.2.2 BGP hijacking for financial gain
            1.10.2.3 Data exfiltration for resale
            
        1.10.3 Insider threat exploitation
            1.10.3.1 Rogue administrator attacks
            1.10.3.2 Privileged credential misuse
            1.10.3.3 Policy manipulation
```

## Why it works

-   Protocol complexity: The RPKI ecosystem involves multiple protocols (RSYNC, RRDP, RTR), cryptographic operations, and distributed repositories, creating a large attack surface.
-   Implementation inconsistencies: Different validator implementations handle edge cases and error conditions differently, leading to vulnerabilities.
-   Human factors: Configuration errors, such as improper MaxLength settings or AS0 authorisations, can inadvertently cause route validation failures.
-   Legacy protocol dependencies: Continued use of RSYNC, despite its known security limitations, introduces vulnerabilities.
-   Trust model complexity: The hierarchical trust model involving RIRs, CAs, and relying parties creates multiple points of potential failure.
-   Monitoring gaps: Many operators lack comprehensive monitoring for RPKI infrastructure, allowing attacks to persist undetected.

## Mitigation

### Repository security hardening
-   Action: Implement comprehensive security controls for RPKI repositories
-   How:
    -   Deploy RRDP instead of RSYNC for improved security and scalability
    -   Implement HTTPS with strong cipher suites and certificate pinning
    -   Use content delivery networks with security monitoring and DDoS protection
-   Configuration example (nginx):

```text
server {
    listen 443 ssl;
    server_name rpki.example.com;
    ssl_certificate /path/to/certificate;
    ssl_certificate_key /path/to/private/key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000";
}
```

### Cryptographic best practices
-   Action: Implement strong cryptographic controls throughout the RPKI ecosystem
-   How:
    -   Use HSMs for private key storage and cryptographic operations
    -   Implement regular key rotation and cryptographic agility
    -   Deploy certificate transparency logging for all issued certificates
-   Best practice: Regular security audits of cryptographic implementations and key management procedures

### Validator security
-   Action: Secure RPKI validator implementations
-   How:
    -   Run validators in restricted environments with minimal privileges
    -   Implement regular security updates and patch management
    -   Use multiple validator implementations for cross-validation
-   Tools: Use security-focused validator implementations with additional integrity checks

### Network security controls
-   Action: Implement network-level protections for RPKI infrastructure
-   How:
    -   Deploy network segmentation between RPKI components
    -   Implement DDoS protection for repository servers
    -   Use intrusion detection systems with RPKI-specific signatures
-   Configuration example: Network ACLs restricting access to RPKI services

### Monitoring and detection
-   Action: Implement comprehensive monitoring for RPKI infrastructure
-   How:
    -   Monitor certificate validity periods and revocation status
    -   Implement anomaly detection for repository access patterns
    -   Use RPKI-specific monitoring tools and dashboards
-   Best practice: Regular review of security monitoring alerts and logs

### Access control and authentication
-   Action: Implement strong access controls for RPKI management interfaces
-   How:
    -   Use multi-factor authentication for all administrative access
    -   Implement role-based access control for RPKI management
    -   Regularly review and audit access permissions
-   Configuration example: 

```bash
# Example: MFA configuration for RPKI management portal
auth required pam_google_authenticator.so
```

### Backup and recovery procedures
-   Action: Implement robust backup and recovery processes
-   How:
    -   Maintain offline backups of critical RPKI components
    -   Test recovery procedures regularly
    -   Implement integrity checking for backup data
-   Best practice: Regular disaster recovery testing and validation

## Key insights from real-world implementations

-   Configuration errors: Many RPKI incidents result from misconfigurations rather than protocol flaws
-   Operational challenges: Maintaining consistent RPKI operations requires significant expertise and resources
-   Adoption barriers: Partial RPKI deployment can create new attack vectors and operational complexities

## Future trends and recommendations

-   Automated validation: Development of machine learning-based anomaly detection for RPKI operations
-   Standardised security: Industry-wide standards for RPKI security implementation and monitoring
-   Improved protocols: Migration from RSYNC to more secure protocols like RRDP
-   Enhanced monitoring: Next-generation monitoring tools with RPKI-specific capabilities

## Conclusion

RPKI infrastructure attacks represent a significant threat to the security of internet routing. These attacks exploit vulnerabilities in the complex RPKI ecosystem, including repository systems, cryptographic implementations, and validation mechanisms. Comprehensive mitigation requires a defence-in-depth approach encompassing repository security, cryptographic best practices, validator security, network controls, and continuous monitoring. As RPKI adoption continues to grow, maintaining robust security practices for RPKI infrastructure is essential for protecting the integrity of global internet routing.
