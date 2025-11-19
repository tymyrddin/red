# Using Scapy in RIPE labs

Scapy is a packet manipulation tool and library. It lets you *build*, *send*, *receive*, and *decode* packets down to the protocol field level. Think of it as `ping` + `tcpdump` + `Wireshark` + a packet foundry, but interactive and scriptable.

## 1. Starting Scapy

```bash
scapy
```

If you see a `>>>` Python-like prompt, you’re in. Quit later with `exit()`, `quit()`, or `Ctrl+D`.

## 2. Building packets

In Scapy, packets are built layer by layer using `/` to stack protocols:

```python
pkt = IPv6(src="2001:db8:5::5", dst="ff02::1") / ICMPv6ND_NA()
```

* `IPv6(...)` → the IPv6 header

  * `src` = source IPv6 address
  * `dst` = destination IPv6 address (`ff02::1` = all nodes on the local link)

* `/ ICMPv6ND_NA()` → attach an ICMPv6 Neighbor Advertisement message on top.

At this point, you have an object called `pkt`. It’s not sent yet, just sitting in memory.

## 3. Sending packets

### 3.1 One-way send

```python
send(pkt)
```

This just fires it off. No listening for replies. Good for testing or attacks where you don’t care about responses.

## 4. Probing with Echo Requests

Let’s try an ICMPv6 ping:

```python
f = IPv6(dst="2001:db8:f:1::1") / ICMPv6EchoRequest()
```

* The `IPv6` layer sets the destination.
* The `ICMPv6EchoRequest()` layer is the IPv6 equivalent of `ping`.

### 4.1 Send and receive

```python
ans, unans = sr(f)
```

* `sr()` = send packet(s) and receive answers.
* `ans` = answered packets (pairs of request + reply).
* `unans` = unanswered packets (request sent, but no reply received).

## 5. Inspecting Results

```python
ans.summary()
```

This gives a one-line overview of request → reply mapping:

```
IPv6 / ICMPv6 Echo Request ==> IPv6 / ICMPv6 Echo Reply
```

For deep inspection:

```python
ans.show()
```

Which prints full decoded layers, e.g.:

```
0000 IPv6 / ICMPv6 Echo Request (id: 0x0 seq: 0x0) ==> 
     IPv6 / ICMPv6 Echo Reply (id: 0x0 seq: 0x0)
```

### 5.1 Accessing individual results

* First request/reply pair:

```python
ans[0]
```

Which is a tuple: `(<sent packet>, <received packet>)`

* Just the reply:

```python
ans[0][1]
```

* Just the request:

```python
ans[0][0]
```

* Show all fields of the request:

```python
ans[0][0].show()
```

Output example:

```text
###[ IPv6 ]###
  version= 6
  tc= 0
  fl= 0
  plen= None
  nh= ICMPv6
  hlim= 64
  src= 2001:db8:f:1:216:3eff:feee:a
  dst= 2001:db8:f:1::1
###[ ICMPv6 Echo Request ]###
  type= Echo Request
  code= 0
  cksum= None
  id= 0x0
  seq= 0x0
```

## 6. Repeated probing with `srloop`

```python
ans, unans = srloop(f)
```

This continuously sends requests until you break it (`Ctrl+C`).

Example output:

```
RECV 1: IPv6 / ICMPv6 Echo Reply (id: 0x0 seq: 0x0)
RECV 1: IPv6 / ICMPv6 Echo Reply (id: 0x0 seq: 0x0)
RECV 1: IPv6 / ICMPv6 Echo Reply (id: 0x0 seq: 0x0)
^C
Sent 3 packets, received 3 packets. 100.0% hits.
```

You can then summarise the results:

```python
ans.summary()
```

## 7. Capturing packets

To capture packets in Scapy, use the `sniff()` function. You need to pass the interface where you want to capture 
packets and define a filtering rule if you do not want to capture all of the packets arriving on that interface.

```python
>>> pkts=sniff(iface="eth0",lfilter = lambda x: x.haslayer(IPv6))
^C
```

## 8. Summary

* Packet composition: Use `/` to stack headers and protocols.
* Sending:

  * `send()` = fire and forget.
  * `sr()` = send and receive (store replies).
  * `srloop()` = send repeatedly until you stop it.
* Inspection:

  * `summary()` for one-liners.
  * `show()` for all fields.
  * Index into `ans` for detailed request/reply tuples.

Scapy does not validate whether fields are "legal". If you want to set insane values (like Flow Label abuse for covert channels), Scapy will happily craft and send it.

## More

[Scapy documentation](https://scapy.readthedocs.io/en/latest/)
