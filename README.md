# 🛡️ 100 Ethical Hacking & Cybersecurity Programming Ideas

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ethical Use Only](https://img.shields.io/badge/Use-Ethically-red)](https://www.hacker101.com/ethics)

A curated collection of **100 programming projects** for learning ethical hacking, penetration testing, and defensive security through hands-on coding.

> **⚠️ IMPORTANT DISCLAIMER**  
> These projects are for **educational purposes only**. Only use them on systems you own or have explicit written permission to test. Unauthorized access is illegal and unethical.

---

## 📚 Table of Contents
- [Why This List?](#why-this-list)
- [Project Categories](#project-categories)
- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Project List](#project-list)
- [Legal & Ethical Guidelines](#legal--ethical-guidelines)
- [Learning Resources](#learning-resources)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Why This List?

Most cybersecurity courses teach **theory** or **tool usage** – but real understanding comes from **building tools yourself**.

By coding these projects, you will:
- ✅ Understand **how attacks actually work** (defender's mindset)
- ✅ Learn **network protocols, cryptography, web security**
- ✅ Build a **portfolio** for security roles
- ✅ Create your own **custom toolchain** for assessments

---

## 📂 Project Categories

| Category | # Projects | Focus Area |
|----------|-----------|------------|
| 🔍 Reconnaissance | 15 | Information gathering, OSINT |
| 🧪 Scanning & Vuln Detection | 15 | Finding weaknesses |
| 💣 Exploitation & Payloads | 10 | Gaining access (authorized) |
| 🔐 Post-Exploitation | 10 | Persistence & pivoting |
| 🌐 Network Manipulation | 11 | Traffic interception |
| 🕸️ Web Hacking Tools | 11 | Web app vulnerabilities |
| 🔬 Forensics & RE | 9 | Analysis & reversing |
| 🛡️ Defense & Hardening | 10 | Building protections |
| 🤖 Automation | 9 | Utility scripts |

---

## 🚀 Getting Started

### Prerequisites

Choose your weapon:

**Language recommendations per category:**
- **Networking / low-level**: Python + `scapy`, `socket`, `ctypes`
- **Web security**: Python (`requests`, `BeautifulSoup`), JavaScript (Node.js)
- **Exploitation**: Python, C, Ruby
- **Forensics**: Python, Go
- **Defense tools**: Python, Bash, Rust

**Tools you'll need:**
```bash
# Python libraries
pip install scapy requests beautifulsoup4 cryptography paramiko

# System tools
nmap                            # testing your scanner
metasploit-framework            # payload reference
wireshark                       # packet inspection
docker                          # safe target environments
```

### Safe Lab Environment

**Never test on real targets.** Use:

1. **Vulnerable VMs** (free):
   - [Metasploitable 2/3](https://docs.rapid7.com/metasploit/metasploitable/)
   - [DVWA (Damn Vulnerable Web App)](https://github.com/digininja/DVWA)
   - [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

2. **Local Docker labs:**
   ```bash
   docker run -d -p 8080:80 vulnerables/web-dvwa
   ```

3. **Your own test network** – isolated VMs or old laptops

---

## 📋 Project List (100 Ideas)

<details>
<summary><b>🔍 Reconnaissance (15)</b></summary>

1. Subdomain enumerator
2. Port scanner
3. Web technology detector
4. Whois lookup tool
5. DNS resolver & record harvester
6. Reverse IP lookup
7. SSL/TLS certificate analyzer
8. Network range to IP list converter
9. Shodan query automation
10. Google dork command-line tool
11. Email harvester
12. GitHub secret scanner
13. Wayback Machine URL fetcher
14. Cloud storage bucket enumerator
15. Link extractor
</details>

<details>
<summary><b>🧪 Scanning & Vulnerability Detection (15)</b></summary>

16. Basic vulnerability scanner
17. Open directory detector
18. CVE checker by service banner
19. WordPress security scanner
20. SQLi detection fuzzer
21. XSS scanner
22. LFI/RFI path tester
23. Command injection detection
24. CRLF injection tester
25. SSRF endpoint tester
26. Open redirect validator
27. Weak cipher scanner
28. FTP anonymous login checker
29. Default credential scanner
30. HTTP method tester
</details>

<details>
<summary><b>💣 Exploitation & Payloads (10)</b></summary>

31. Reverse shell generator
32. Bind shell server
33. Metasploit payload encoder
34. SQLMap tamper script writer
35. Buffer overflow fuzzer
36. ROP gadget finder
37. Web shell generator
38. File upload bypasser
39. Payload encryptor/decryptor
40. Macro generator for Office docs
</details>

<details>
<summary><b>🔐 Post-Exploitation (10)</b></summary>

41. Privilege escalation checker (Linux)
42. Privilege escalation checker (Windows)
43. Persistence via scheduled task
44. Persistence via cron
45. Password hash dumper (simulated)
46. Mimikatz-like credential scraper
47. Keylogger (authorized only)
48. Screenshot capturer
49. Browser credential extractor
50. Local enumeration report generator
</details>

<details>
<summary><b>🌐 Network & Traffic Manipulation (11)</b></summary>

51. ARP spoofer
52. DNS spoofer
53. Packet sniffer
54. HTTP/HTTPS proxy
55. TCP session hijacker
56. MAC address changer
57. Deauthentication attack tool
58. Evil twin access point
59. Netcat-like relay
60. ICMP exfiltration tunnel
61. DNS tunneling client
</details>

<details>
<summary><b>🕸️ Web Application Hacking Tools (11)</b></summary>

62. Login brute-forcer
63. CSRF proof-of-concept generator
64. JWT token cracker
65. Session ID entropy checker
66. CORS misconfiguration scanner
67. GraphQL introspection dumper
68. API rate limit tester
69. Clickjacking frame-buster buster
70. HTTP request smuggling detector
71. NoSQL injection tester
</details>

<details>
<summary><b>🔬 Forensics & Reverse Engineering (9)</b></summary>

72. PE file parser
73. ELF file analyzer
74. String extractor
75. Simple debugger (Linux)
76. Hash calculator
77. Memory dump analyzer
78. Log parser for auth attacks
79. PCAP to HTTP request reconstructor
80. Registry hive viewer
</details>

<details>
<summary><b>🛡️ Defense & Hardening Tools (10)</b></summary>

81. File integrity monitor
82. Honeypot (low-interaction)
83. Port knocking daemon
84. Ransomware simulation tool
85. SQL injection firewall
86. Fail2ban-like log watcher
87. SSH brute-force blocker
88. Secure delete utility
89. Password strength tester
90. System call logger
</details>

<details>
<summary><b>🤖 Automation & Utility Scripts (9)</b></summary>

91. Wordlist generator
92. Base64/URL/Hex encoder/decoder
93. IP geolocation mapper
94. Leaked password checker (offline)
95. SSH key pair manager
96. Tor proxy wrapper
97. Automatic report formatter
98. API version fuzzer
99. Command-line pastebin scraper
100. Cron job monitoring script
</details>

---

## ⚖️ Legal & Ethical Guidelines

### ✅ You MAY:
- Test on **your own computers, networks, or VMs**
- Test on **explicitly authorized** bug bounty programs
- Use in **CTF competitions** and **hackathons**
- **Study and modify** code for learning

### ❌ You MAY NOT:
- Scan or attack **any system without permission**
- Use for **actual cybercrime** (data theft, ransomware, etc.)
- Distribute malicious variants of these tools
- Violate **your local computer misuse laws**

### 📜 Sample Authorization Form (for professional use)
```
I, [NAME], authorize [YOUR NAME] to perform security testing
on [DOMAIN/NETWORK] from [DATE] to [DATE].
Contact: [SIGNATURE]
```

---

## 📖 Learning Resources

**Free & Legal Practice:**
- [HackTheBox Academy](https://academy.hackthebox.com/) (free tier)
- [TryHackMe](https://tryhackme.com/) (free rooms)
- [PentesterLab](https://pentesterlab.com/) (free exercises)
- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/)

**Reference Books:**
- *The Web Application Hacker's Handbook* (Stuttard & Pinto)
- *Hacking: The Art of Exploitation* (Erickson)
- *Penetration Testing: A Hands-On Introduction* (Georgia Weidman)

**Python for Hackers:**
- [Scapy documentation](https://scapy.readthedocs.io/)
- [Python Pentesting Tools (GitHub)](https://github.com/dloss/python-pentest-tools)

---

## 🤝 Contributing

Found a bug in an implementation? Have a better idea for project #101?

1. Fork the repo
2. Create a branch (`git checkout -b idea-improvement`)
3. Commit your changes
4. Open a Pull Request

**Guidelines:**
- Keep tools **educational** (no ready-to-use malware)
- Add **safe guardrails** (warnings, permission checks)
- Include **usage examples** with lab targets

---

## 📄 License

MIT License – feel free to use, modify, and share for **legal, educational purposes**.

*By using this repository, you affirm that you will comply with all applicable laws and ethical guidelines.*

---

## ⭐ Show Your Support

If this list helps you learn cybersecurity, **star this repo** and share it responsibly!

> **Remember:** With great power comes great responsibility. 🕸️

---

### 📬 Contact / Questions

- **Ethical concerns?** Open an Issue (confidential)
- **Want to collaborate?** DM or email
- **Report a bug** in a specific tool implementation

**Stay curious, stay legal, stay secure.**

