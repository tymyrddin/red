# CISCO Salted Password

Your company’s network administrator forgot his administration passwords. He does however have [a backup of his startup-config file](https://www.root-me.org/en/Challenges/Cryptanalysis/CISCO-Salted-Password). Use it to recover his passwords! The flag is the concatenation of the **enable** and **administrator** passwords.

```text
{!
version 15.1
no service timestamps log datetime msec
no service timestamps debug datetime msec
no service password-encryption
!
hostname R1
!
enable secret 5 $1$mERr$A419.HL58lq743wXS4kSM1
!
ip cef
no ipv6 cef
!
username administrator secret 5 $1$mERr$yhf7f2RnC74CxKANvoekD.
!
license udi pid CISCO2911/K9 sn FTX1524V4VG-
!
no ip domain-lookup
!
spanning-tree mode pvst
!
interface GigabitEthernet0/0
 ip address 10.0.0.254 255.255.255.0
 no ip proxy-arp
 duplex auto
 speed auto
!
interface GigabitEthernet0/1
 ip address 11.0.0.1 255.255.255.252
 no ip proxy-arp
 duplex auto
 speed auto
!
interface GigabitEthernet0/2
 no ip address
 duplex auto
 speed auto
 shutdown
!
interface Vlan1
 no ip address
 shutdown
!
router bgp 1
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes
 no synchronization
 neighbor 11.0.0.2 remote-as 2
 network 10.0.0.0 mask 255.255.255.0
!
ip classless
!
ip flow-export version 9
!
no cdp run
!
line con 0
 login local
!
line aux 0
!
line vty 0 4
 login
!
!
!
}
```

The file contains a Cisco **administrator secret 5** password `username administrator secret 5 $1$mERr$yhf7f2RnC74CxKANvoekD.`. Also needed to get the flag is the **enable secret 5** password: `enable secret 5 $1$mERr$A419.HL58lq743wXS4kSM1`.

Structure:

```text
$1$mERr$A419.HL58lq743wXS4kSM1
 ^   ^    ^
 |   |    |
 |   |    `-> Hash (salt + password)
 |   |
 |   `-> base64 salt (4 chars.)
 |
 `-> Hash type (md5)
```

On cracking with hashcat or John the Ripper:

| Cisco  | Crackability | John the Ripper             | Hashcat |
|:-------|:-------------|:----------------------------|:--------|
| Type 0 | instant      | n/a                         | n/a     |
| Type 7 | instant      | n/a                         | n/a     |
| Type 4 | easy         | --format=Raw-SHA256         | -m 5700 |
| Type 5 | medium       | --format=md5crypt           | -m 500  |
| Type 8 | hard         | --format=pbkdf2-hmac-sha256 | -m 9200 |
| Type 9 | very hard    | --format=scrypt             | -m 9300 |


Cracking the administrator password:

`hash.txt`:

```text
administrator:$1$mERr$yhf7f2RnC74CxKANvoekD.
```

Using `hashcat`:

```text
hashcat -m 500 --username -O -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Cracking the enable password:

`hash.txt`:

```text
$1$mERr$A419.HL58lq743wXS4kSM1
```

Using `hashcat`:

```text
hashcat -m 500 -O -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

I also tried [IFM](https://www.ifm.net.nz/cookbooks/cisco-ios-enable-secret-password-cracker.html), just to see it work:

[![IFM 5](/_static/images/ifm5.png)](https://www.ifm.net.nz/cookbooks/cisco-ios-enable-secret-password-cracker.html)

It was extremely slow, and I broke it off after an hour.

The flag is the concatenation of the enable and administrator passwords, in that order.

## Resources

* [Cisco Password Cracking and Decrypting Guide](https://www.infosecmatter.com/cisco-password-cracking-and-decrypting-guide/)
