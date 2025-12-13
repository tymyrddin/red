Absolutely. Let’s expand this page so it’s **hands-on**, beginner-friendly, and practical with real lab commands, expected outputs, and explanations for **each technique**.

---

# Locally Scanning IPv6 Networks

If you have access to a network link, you can discover active IPv6 addresses and devices on the local network. This is called **local scanning**. In this guide, you will learn several ways attackers (or network administrators) can map local IPv6 networks. All commands work in the RIPE labs environment.

---

## 1. Traffic Snooping

**What it is:** Capturing packets on the local network to see which devices are active.

**Tools in the lab:** `Termshark` (pre-installed in RIPE labs), Wireshark, or `tcpdump`.

**How to do it:**

1. Start Termshark:

   ```bash
   termshark
   ```

   * Press `:` to open the command menu.
   * Use `Ctrl+N` to start capturing packets on the default interface.

2. Apply a display filter for IPv6 traffic:

   ```
   ipv6
   ```

3. Observe source (`src`) and destination (`dst`) addresses in captured packets. Active hosts on the link will appear here.

**Example output in Termshark:**

```
No.  Time       Source                  Destination             Protocol Info
1    0.000000   fe80::216:3eff:feee:a  ff02::1                 ICMPv6 Neighbor Solicitation
2    0.100000   fe80::216:3eff:feee:b  ff02::1                 ICMPv6 Neighbor Advertisement
```

**Why it works:** IPv6 devices constantly send packets like NDP announcements, allowing you to see them without actively probing.

---

## 2. Dual-Stack Observation

**What it is:** Using information from a host’s IPv4 configuration to infer its IPv6 address.

**Example:**

* IPv4 host: `192.0.2.5`
* MAC address: `00:16:3e:ee:aa:bb`

IPv6 SLAAC often generates IIDs based on the MAC address using **EUI-64**. You can calculate a likely IPv6 address:

```
IPv6 IID: fe80::216:3eff:feee:aabb
Full IPv6: 2001:db8:5::216:3eff:feee:aabb
```

**Why it works:** SLAAC with EUI-64 makes addresses predictable.

---

## 3. Routing Protocol Analysis

**What it is:** Observing routing announcements to map local networks.

**Tools:** Termshark or `tcpdump`.

**Example:** Capture OSPFv3 Hello packets:

```bash
sudo tcpdump -i eth0 -n ip6 proto ospf
```

**Output:**

```
16:15:01 OSPFv3 Hello packet from fe80::216:3eff:feee:a on eth0
```

**Explanation:** Hello packets reveal link-local addresses and network topology.

---

## 4. Local Protocol Discovery

**What it is:** Use protocols like NDP to find neighbors.

**Tool in RIPE labs:** `ndisc6`

**Command:**

```bash
ndisc6 -q 2001:db8:5::1 eth0
```

**Explanation:**

* `-q` queries the target IPv6 address.
* If active, you receive a Neighbor Advertisement (NA).

**Why it works:** NDP and MLD are required for IPv6 communication on the link.

---

## 5. Active Local Scanning

**What it is:** Probing addresses to see if they respond.

**Tools:** `ping6`, `nmap -6`

**Examples:**

* Ping a specific address:

```bash
ping6 -c 1 2001:db8:5::1
```

* Scan a range of addresses:

```bash
nmap -6 -p 80 2001:db8:5::1-10
```

**Output:**

```
Host 2001:db8:5::1 is up
Host 2001:db8:5::2 is up
```

**Why it works:** Low IIDs and sequential addresses make guessing feasible.

---

## 6. Combining Methods

* Start with **traffic snooping** to see which addresses are active.
* Use **dual-stack information** and **local protocol discovery** to refine your target list.
* Finish with **active scanning** to confirm which hosts respond and which ports are open.

---

## Lab Safety

*Only scan networks you are authorised to. In the RIPE lab environment, all these methods are safe to practice.*


