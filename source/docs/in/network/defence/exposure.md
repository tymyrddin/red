# Reducing network attack surface

Network exposure is reduced by eliminating unnecessary services, hardening protocol configurations, and enforcing authentication where protocols currently trust by default. The specific controls below map to the attack techniques documented in the network notes and runbooks.

## Layer 2 hardening

Dynamic ARP inspection validates ARP packets against a trusted DHCP snooping binding table, dropping ARP replies where the claimed IP-to-MAC mapping does not match a known DHCP lease. This prevents ARP poisoning attacks that rely on sending gratuitous ARP replies.

```
! Cisco IOS
ip arp inspection vlan 10,20,30
interface GigabitEthernet0/1
 ip arp inspection limit rate 100
```

DHCP snooping must be enabled first, as DAI uses its binding table:

```
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
interface GigabitEthernet0/1
 ip dhcp snooping trust  ! Only on uplinks/DHCP server ports
```

Disable DTP on all non-trunk ports to prevent switch spoofing VLAN hopping:

```
interface GigabitEthernet0/1
 switchport mode access
 switchport nonegotiate
```

BPDU guard prevents unauthorised switches from participating in STP:

```
interface GigabitEthernet0/1
 spanning-tree bpduguard enable
```

## Disabling LLMNR and NBT-NS

LLMNR and NBT-NS provide no security benefit that cannot be provided by properly functioning DNS. Disabling them eliminates the primary mechanism for Responder-style credential capture on Windows networks.

Group Policy to disable LLMNR:

```
Computer Configuration > Administrative Templates > Network > DNS Client
  Turn off multicast name resolution = Enabled
```

NBT-NS is disabled per-adapter through DHCP option 001 or registry:

```powershell
# Disable NBT-NS via registry on all adapters
Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
  Where-Object {$_.IPEnabled -eq $true} |
  ForEach-Object {$_.SetTcpipNetbios(2)}
```

## SMB signing

SMB signing authenticates every SMB message with a cryptographic signature, preventing NTLM relay attacks against SMB. It should be required on all domain controllers and enforced on all domain-joined workstations and servers via Group Policy.

```
Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
  Microsoft network client: Digitally sign communications (always) = Enabled
  Microsoft network server: Digitally sign communications (always) = Enabled
```

## Kerberos hardening

Managed service accounts and group managed service accounts use 240-character automatically rotated passwords, making Kerberoasting infeasible even if tickets are captured. All service accounts that do not require legacy authentication should be migrated to gMSA.

AES-only Kerberos encryption should be enforced on sensitive accounts:

```powershell
Set-ADUser -Identity svcaccount -KerberosEncryptionType AES128,AES256
```

Pre-authentication should be required on all accounts. Accounts with the `DONT_REQ_PREAUTH` flag are AS-REP roastable:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} |
  Set-ADAccountControl -DoesNotRequirePreAuth $false
```

## Wireless security

WPA3 should be the minimum standard for any new wireless deployment. For existing WPA2 deployments, PMF (Protected Management Frames) should be enabled to prevent deauthentication frame injection. WPA2 networks should use CCMP rather than TKIP.

For enterprise wireless using 802.1X, clients must validate the RADIUS server certificate. This requires deploying the corporate CA certificate to clients and configuring the supplicant to reject connections to servers presenting unexpected certificates. Without this configuration, rogue AP attacks capturing MSCHAPv2 exchanges are trivial.

## Network segmentation and routing controls

BCP 38 egress filtering at network boundaries drops packets with source addresses that do not belong to the originating prefix, preventing IP spoofing across provider boundaries. Internal networks should apply equivalent controls at segment boundaries.

Route filter policies should restrict BGP announcements to authorised prefixes. RPKI ROAs published for all announced prefixes allow downstream networks to reject invalid route announcements via BGPsec-capable routers.
