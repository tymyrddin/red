# Using termshark in RIPE labs

`termshark` is a terminal-based user interface for `tshark`, giving you a Wireshark-like experience inside the terminal. It is especially handy in environments like RIPE Labs, where GUI tools are not available.

## Starting termshark

In RIPE Labs, simply run:

```bash
termshark
```

* No `sudo` is required.
* You do not need to specify an interface; `termshark` will automatically pick a default.

## Basic navigation

The `termshark` interface is split into three panes (similar to Wireshark):

1. Packet list (top) – one line per captured packet.
2. Packet details (middle) – a tree view showing decoded protocol layers.
3. Packet bytes (bottom) – the raw hex and ASCII view of the packet.

Navigation works as follows:

* Arrow keys / `PgUp` / `PgDn`: Move through packets.
* Tab: Cycle between panes.
* Right / Left Arrow: Expand or collapse fields in the details pane.
* Enter: Expand a field or drill deeper into a protocol layer.

## Command menu

`termshark` borrows from `less`/`vim` conventions.

* Press `:` (colon) to open the command prompt at the bottom.
* Some useful commands:

  * `:q` – quit termshark.
  * `:help` – view help.
  * `:filter <expression>` – apply a display filter (e.g. `:filter icmp`).
  * `:clear-filter` – remove the active filter.

Tip: Display filters use the same syntax as Wireshark (`ip.addr == 192.0.2.1`, `tcp.port == 443`, etc.).

## Searching packets

To search within captured packets:

* Press `/` and type your search string.
* Press `n` to jump to the next match, `N` to jump to the previous one.

## Capture filters vs display filters

* Capture filters: Set at startup with `-f`. Example:

```bash
termshark -i eth0 -f "port 53"
```

  Only DNS traffic will be captured.

* Display filters: Applied interactively with `:filter`. Example:

```
:filter icmpv6
```

  All captured packets remain, but only ICMPv6 is shown.

## Example workflows

1. View IPv6 neighbour advertisements:

```bash
termshark -i eth0
```

   Then run:

```
:filter icmpv6.type == 136
```

2. Follow a TCP stream:

   * Highlight a TCP packet.
   * Press `s` to open the "Follow Stream" view.
   * Use arrow keys to scroll through the conversation.

## Quitting termshark

There are several ways to quit:

* Press `q` while in the packet list pane.
* Or press `:` then type `q` and hit Enter.
* Or `Ctrl+C` if all else fails.

## More

[Termshark User Guide](https://github.com/gcla/termshark/blob/master/docs/UserGuide.md)
