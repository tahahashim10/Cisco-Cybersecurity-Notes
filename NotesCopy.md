### Traditional Data:
- **Transactional Data**: Information related to transactions, production, and employment decisions.
- **Intellectual Property**: Includes patents and trade secrets that give a competitive advantage.
- **Financial Data**: Income statements, balance sheets, and cash flow statements reflect a company's financial health.

### Types of Attackers:
- **White Hat**: Ethical hackers who identify security weaknesses with permission.
- **Gray Hat**: Hackers who may report or disclose vulnerabilities based on their agenda.
- **Black Hat**: Hackers exploiting vulnerabilities for illegal gain.

### Malware:
- **Spyware**: Monitors and logs user activities, often bundled with legitimate software.
- **Adware**: Delivers ads, often accompanied by spyware.
- **Backdoor**: Provides unauthorized access to a system.
- **Ransomware**: Holds systems or data hostage until payment is made.
- **Scareware**: Tricks users into running malware by creating fake warnings.
- **Rootkit**: Modifies system files to create backdoor access, often requiring a complete system wipe to remove.
- **Virus**: Self-replicating code that attaches to executable files, spread by user interaction.
- **Trojan Horse**: Appears legitimate but executes malicious activities without self-replicating.
- **Worms**: Self-replicating malware that spreads without user intervention, causing widespread damage.

### Social Engineering:
- **Manipulation**: Attackers trick people into divulging information or performing actions.
- **Pretexting**: Attackers lie to gain access to privileged data.
- **Tailgating**: Following an authorized person into a secure area.
- **Quid Pro Quo**: Exchanging personal information for a promised reward.

### Denial-of-Service (DoS) & Distributed DoS (DDoS):
- **DoS**: Disrupts services by overwhelming the network or sending maliciously formatted packets.
- **DDoS**: Multiple sources (botnet of infected hosts) coordinate to launch an attack.

### On-Path Attacks:
- **MitM**: Intercepts and manipulates communications between devices.
- **MitMo**: Targets mobile devices to steal sensitive data, often through malware.

### Password Attacks:
- **Password Spraying**: Attempts a few common passwords across many accounts.
- **Dictionary Attacks**: Tries every word in a list to guess a password.
- **Brute-Force Attacks**: Tests all possible password combinations.
- **Rainbow Attacks**: Uses precomputed hash values to match stored passwords.
- **Traffic Interception**: Reads unencrypted passwords by intercepting communications.

### Advanced Persistent Threats (APTs):
- **APTs**: Stealthy, long-term attacks often carried out by skilled, well-funded groups targeting organizations or nations.

### Hardware Vulnerabilities:
- **Rowhammer**: Exploits electrical interference in RAM to corrupt data.
- **Meltdown & Spectre**: Side-channel attacks that can read system memory, affecting CPUs since 1995.

### Software Vulnerabilities:
- **SYNful Knock**: Compromises routers to monitor and infect network devices.
- **Buffer Overflow**: Writes data beyond buffer limits, causing crashes or privilege escalation.
- **Non-Validated Input**: Malicious input forces programs to behave unexpectedly.
- **Race Conditions**: Vulnerabilities from incorrect timing or ordering of events.
- **Weak Security Practices**: Insecure custom security algorithms introduce vulnerabilities.
- **Access Control Problems**: Poor management of who can access resources leads to security breaches.

### Cryptocurrency:
- **Cryptocurrency**: Digital money using encryption for transactions, managed via blockchain without third-party involvement.
- **Cryptojacking**: Uses a victim's device resources to mine cryptocurrency without their consent.

### Device and Network Protection:
- **Firewalls**: Use software or hardware firewalls to prevent unauthorized access.
- **Antivirus & Antispyware**: Protect against viruses and spyware; regularly update software.
- **Operating System and Browser Management**: Regularly update OS and browsers to prevent exploitation of vulnerabilities.
- **Password Protection**: Password-protect devices and encrypt sensitive data; change default router settings.
- **Wireless Network Security**: Change SSID and default passwords on routers and enable WPA2 encryption for wireless communication.

### Public Wi-Fi Risks
- Always verify that your device isn’t configured with file and media sharing and requires user authentication with encryption.
- Use an encrypted VPN service to prevent eavesdropping. A VPN secures your internet access by encrypting the connection between your device and the VPN server. Even if data is intercepted, it remains undecipherable.

### Data Maintenance

**How to Encrypt Data:**
- Encrypting File System (EFS) on Windows can secure data, linked to a specific user account.
1. Select files or folders.
2. Right-click and choose ‘Properties.’
3. Click ‘Advanced’ and check ‘Encrypt contents to secure data.’
- Encrypted files appear in green.

**Deleting Data Permanently:**
- Simply deleting a file leaves traces recoverable by forensic tools.
- To erase data irrecoverably, overwrite it with ones and zeroes using tools like SDelete for Windows or Shred for Linux. Physically destroying the hard drive is the only way to ensure data is completely unrecoverable.
- Remember to delete data stored online in the cloud as well.

### Who Owns Your Data
- **Terms of Service Agreement**: A legally binding contract that governs your relationship with a service provider and other users.
    - **Data Use Policy**: Outlines how the service provider collects, uses, and shares your data.
    - **Privacy Settings**: Control who can see your information and access your profile.
    - **Security Policy**: Defines how the company secures the data it collects.

### Safeguarding Your Online Privacy
- **Two-Factor Authentication (2FA)** adds an extra security layer.
- **Open Authorization (OAuth)**: Allows you to use credentials to access third-party apps without exposing your password.
- **Private Browsing Mode**: Disables cookies and deletes browsing history after closing the window, reducing tracking.
- Despite private browsing, companies can still track your behavior through devices like routers.
- **Password Manager Applications**: Securely encrypt and store passwords, generating random passwords for different accounts.

### Cybersecurity Devices and Technologies

**Security Appliances:**
- **Routers**: Interconnect network segments, with basic traffic filtering.
- **Firewalls**: Inspect traffic for malicious behavior and block threats.
- **Intrusion Prevention Systems (IPS)**: Block malicious traffic using signature-based detection.
- **VPNs**: Provide secure, encrypted tunnels for remote connections.
- **Antimalware/Antivirus**: Detect and block malicious code.

**Firewalls:**
- Control which communications are allowed in and out of a device or network.
    - **Network Layer Firewall**: Filters by source and destination IP addresses.
    - **Transport Layer Firewall**: Filters by data ports and connection states.
    - **Application Layer Firewall**: Filters by application, program, or service.
    - **Content-Aware Layer Firewall**: Filters based on user, device, role, and threat profile.
    - **NAT Firewall**: Masquerades private network addresses.

**Port Scanning:**
- Probes for open ports on a device or network host, which can be used maliciously to find vulnerabilities or harmlessly to verify network security.

**Intrusion Detection & Prevention Systems (IDS/IPS):**
- **IDS**: Detects and logs malicious traffic, alerting administrators.
- **IPS**: Blocks traffic based on detected threats in real-time, with systems like Snort or Cisco's Sourcefire.

**Real-Time Detection:**
- Detecting attacks in real-time requires scanning with IDS/IPS, firewalls, and next-gen malware detection. DDoS attacks are a significant threat, needing immediate response.

**Behavior-Based Security:**
- Captures and analyzes communication patterns to detect anomalies. **Honeypots** are traps for attackers, used to study their behavior.

**NetFlow**: Monitors and reports data flow through networks, aiding behavior-based detection by establishing normal behavior baselines.

**Penetration Testing (Pen Testing):**
1. **Planning**: Gather information and identify vulnerabilities.
2. **Scanning**: Probe for weaknesses via port or vulnerability scanning.
3. **Gaining Access**: Exploit vulnerabilities to gain entry.
4. **Maintaining Access**: Stay undetected while gathering valuable data.
5. **Reporting**: Provide feedback to strengthen defenses.

### Risk Management
- **Risk Management**: A continuous process to identify, assess, and mitigate risks.
    - **Frame the Risk**: Identify potential threats, including attacks, process failures, and legal liabilities.
    - **Assess the Risk**: Prioritize threats based on impact, either financial (quantitative) or operational (qualitative).
    - **Respond to the Risk**: Create action plans to reduce risk through elimination, mitigation, transfer, or acceptance.
    - **Monitor the Risk**: Review threats that cannot be eliminated and adjust as needed.

### Cisco's CSIRT
- Cisco's Computer Security Incident Response Team (CSIRT) takes a proactive approach to security, collaborating with organizations like FIRST and DSIE to prevent security incidents.

### Tools for Incident Detection and Prevention
- **SIEM (Security Information and Event Management)**: Collects and analyzes security data to detect attacks early.
- **DLP (Data Loss Prevention)**: Monitors and protects data in use, in motion, and at rest, preventing unauthorized access.

### Cisco ISE and TrustSec
- These enforce user access to network resources through role-based access policies.

### Cybersecurity Certifications
- **Cisco Certified Support Technician (CCST)**: Entry-level certification for those starting in cybersecurity.
- **CompTIA Security**: Entry-level security certification recognized by the U.S. Department of Defense.
- **EC Council Certified Ethical Hacker (CEH)**: Tests knowledge of ethical hacking techniques.
- **ISC2 Certified Information Systems Security Professional (CISSP)**: A top-level security certification requiring five years of experience.
- **Cisco Certified CyberOps Associate**: Validates skills needed for cybersecurity analysts in security operations centers.