# Deep Packet Translator & IGMPv2 Multicast Tool

This project is something I built from scratch to learn and show I know how raw networking works. No high-level abstractions. I'm crafting Ethernet frames by hand, calculating checksums, injecting session IDs into MAC addresses, and managing translation logic manually.

It is a mix between a NAT device, an IGMP multicast client, and a custom ASCII-over-Ethernet protocol playground.

## 🚀 What It Does

### TranslateManager

TranslateManager listens for incoming packets and inspects their type. If it detects an IPv4 packet that matches any defined translation subnet, it rewrites the source or destination IP depending on direction. It embeds session IDs into the MAC address so it can track replies from the target back to the origin.

It also calculates and patches both IP and TCP checksums after rewriting the packets, which is critical for keeping packets valid and routable.

### Session Tracking

Each unique client that sends packets through the system is assigned a session ID. This ID is embedded in the last two bytes of the sender's MAC address. It allows TranslateManager to associate reply packets with the original sender and forward them accordingly.

TranslatorRecords maintain a list of active sessions, expiring after 5 minutes of inactivity. If an expired session exists, it can be reused instead of allocating a new ID.

### ARP Spoofing and Handling

When an ARP reply comes in and matches a translation rule, TranslateManager responds with its own ARP reply. The reply includes a forged MAC address that contains the session ID. This tricks the sender into directing future traffic through this system. It acts like a proxy router.

### IGMPv2 and Multicast

IGMPv2 is used to join multicast groups. The IGMPv2 class manually constructs a Join packet, converts the multicast IP into a multicast MAC, and sends the packet using raw Ethernet.

Once joined, it listens for multicast packets on that group with a specific Ethertype (0x2322). It filters packets by MAC address and logs the ASCII content if it matches. This provides a way to build a multicast chat system over raw Ethernet.

### Custom ASCII Protocol

SimpleAsciiProtocol is a layer that turns a string into ASCII-encoded bytes. These are then wrapped in a raw Ethernet frame and sent to the multicast MAC. When received, the packet is printed as a string to the console.

## ⚙️ How It Works

Built entirely in C# using SharpPcap to access the raw network interface. Instead of relying on sockets or high-level APIs, it opens a pcap device and intercepts every incoming and outgoing packet manually.

When a packet arrives:

1. The destination MAC is checked to see if it matches the NIC's MAC range.
2. If it is an IP packet, the source or destination IP is matched against translation rules.
3. If a match is found, the packet is rewritten:

   * The source or destination IP is updated.
   * The MAC addresses are changed.
   * A new session ID is assigned or reused.
   * The IP checksum is recalculated.
   * If TCP, the TCP checksum is recalculated.
4. If it's an ARP reply, an ARP response is sent with a spoofed MAC.
5. If it’s a reply packet from the target, the session ID in the MAC helps locate the original sender.

## 📁 Files

TranslateManager.cs handles packet capture, translation, and rewriting logic

Translator.cs defines a source CIDR and destination IP mapping

TranslatorRecord.cs keeps track of who sent what and when for reply association

IGMPv2.cs sends multicast join messages and listens for ASCII packets

SimpleAsciiProtocol.cs wraps plain text into a raw Ethernet payload

Program.cs sets up and starts the translation environment

## 💡 Why I Made This

I built this to explore how real network traffic works. To go beyond what the socket layer shows you and actually manipulate the packets themselves. This project gave me a deeper understanding of protocols like ARP, IGMP, TCP, and IPv4, and showed me how routers, switches, and firewalls really behave at the binary level.

Yes, this was for learning. But it also proves I know what I’m doing.





