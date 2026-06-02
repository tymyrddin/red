# Cloud metadata service abuse via ICMP

## Attack pattern

Cloud metadata service abuse via ICMP represents a sophisticated attack methodology that leverages the Internet 
Control Message Protocol to interact with and exploit cloud instance metadata services. These techniques enable 
attackers to discover, query, and harvest sensitive information from cloud metadata services while potentially 
evading traditional security controls designed for HTTP-based metadata access.

```text
1. Cloud metadata service abuse [OR]

    1.1 IMDS exploitation [OR]
    
        1.1.1 ICMP-based IMDSv1 queries
            1.1.1.1 AWS instance metadata service discovery via ICMP
            1.1.1.2 Metadata harvesting through crafted ICMP packets
            1.1.1.3 Instance role credential extraction via ICMP
            1.1.1.4 User data retrieval through ICMP manipulation
            
        1.1.2 Instance metadata service discovery
            1.1.2.1 Cloud provider metadata endpoint identification
            1.1.2.2 Metadata service version detection via ICMP
            1.1.2.3 Regional metadata service discovery
            1.1.2.4 Multi-cloud metadata service enumeration
            
        1.1.3 Cloud credential harvesting
            1.1.3.1 Temporary security credential extraction
            1.1.3.2 IAM role information gathering
            1.1.3.3 Access key ID and secret key harvesting
            1.1.3.4 Session token collection through ICMP
            
    1.2 Serverless SSRF attacks [OR]
    
        1.2.1 ICMP-triggered serverless SSRF
            1.2.1.1 Lambda function metadata service access via ICMP
            1.2.1.2 Cloud function metadata exploitation
            1.2.1.3 Serverless environment credential harvesting
            1.2.1.4 Function-as-a-service metadata compromise
            
        1.2.2 Container metadata service access
            1.2.2.1 Kubernetes pod metadata service targeting
            1.2.2.2 Container role credential extraction
            1.2.2.3 Docker container metadata exploitation
            1.2.2.4 Container orchestration platform metadata access
            
        1.2.3 Kubernetes API server targeting
            1.2.3.1 API server discovery via ICMP techniques
            1.2.3.2 Service account token harvesting
            1.2.3.3 Cluster metadata extraction
            1.2.3.4 Kubernetes role-based access control bypass
            
    1.3 Cloud network reconnaissance [OR]
    
        1.3.1 VPC metadata discovery via ICMP
            1.3.1.1 Virtual private cloud configuration analysis
            1.3.1.2 Subnet and routing table information gathering
            1.3.1.3 Network access control list enumeration
            1.3.1.4 Cloud router configuration discovery
            
        1.3.2 Cloud security group mapping
            1.3.2.1 Security group rule inference through ICMP responses
            1.3.2.2 Network security policy enumeration
            1.3.2.3 Inbound and outbound rule discovery
            1.3.2.4 Implicit deny rule identification
            
        1.3.3 Service endpoint discovery
            1.3.3.1 Private service endpoint identification
            1.3.3.2 Cloud service interface discovery
            1.3.3.3 API gateway endpoint enumeration
            1.3.3.4 Load balancer and proxy service mapping
            
    1.4 Metadata service evasion [OR]
    
        1.4.1 Hop limit manipulation
            1.4.1.1 TTL/hop limit adjustment for local metadata access
            1.4.1.2 Route manipulation to reach metadata services
            1.4.1.3 Network namespace traversal techniques
            1.4.1.4 Container escape via metadata service targeting
            
        1.4.2 Protocol conversion attacks
            1.4.2.1 ICMP to HTTP protocol conversion for metadata access
            1.4.2.2 Packet crafting for service communication
            1.4.2.3 Protocol tunnelling through ICMP
            1.4.2.4 Metadata service API call simulation
            
    1.5 Persistence and access maintenance [OR]
    
        1.5.1 Credential persistence techniques
            1.5.1.1 Regular credential refresh through automated queries
            1.5.1.2 Long-lived access maintenance
            1.5.1.3 Token renewal automation
            1.5.1.4 Credential caching and storage
            
        1.5.2 Access expansion methods
            1.5.2.1 Privilege escalation through harvested credentials
            1.5.2.2 Lateral movement using cloud credentials
            1.5.2.3 Cross-account access achievement
            1.5.2.4 Service role assumption attacks
            
    1.6 Cloud provider-specific exploitation [OR]
    
        1.6.1 Multi-cloud metadata targeting
            1.6.1.1 AWS instance metadata service exploitation
            1.6.1.2 Azure instance metadata service targeting
            1.6.1.3 Google cloud metadata service access
            1.6.1.4 Oracle cloud infrastructure metadata exploitation
            
        1.6.2 Provider-specific feature abuse
            1.6.2.1 Cloud-specific metadata field exploitation
            1.6.2.2 Custom metadata service feature targeting
            1.6.2.3 Provider-specific API endpoint discovery
            1.6.2.4 Unique cloud service metadata access
```

## Why it works

-   Protocol necessity: ICMP is essential for network operations and cannot be completely blocked
-   Metadata service accessibility: Cloud metadata services are designed to be easily accessible from instances
-   Security control gaps: Many cloud security controls focus on HTTP traffic while overlooking ICMP
-   Instance trust assumptions: Cloud platforms inherently trust instance-originated communications
-   Protocol conversion: ICMP can be used to trigger or facilitate other protocol communications
-   Monitoring limitations: Cloud monitoring often lacks deep ICMP analysis capabilities

## Counter moves

Cloud metadata service abuse via ICMP is the case here. Filtering and rate-limiting ICMP, and watching for tunnelling, are the counters. Seen from the other side, this sits in the blue notes on [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
