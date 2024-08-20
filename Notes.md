Traditional Data
- Transactional data such as details relating to buying and selling, production activities and basic organizational operations such as any information used to make employment decisions.
- Intellectual property such as patents, trademarks and new product plans, which allows an organization to gain economic advantage over its competitors. This information is often considered a trade secret and losing it could prove disastrous for the future of a company.
- Financial data such as income statements, balance sheets and cash flow statements, which provide insight into the health of a company.

Types of Attackers
- White hat attackers break into networks or computer systems to identify any weaknesses so that the security of a system or network can be improved. These break-ins are done with prior permission and any results are reported back to the owner.
- Gray hat attackers may set out to find vulnerabilities in a system but they will only report their findings to the owners of a system if doing so coincides with their agenda. Or they might even publish details about the vulnerability on the internet so that other attackers can exploit it.
- Black hat attackers take advantage of any vulnerability for illegal personal, financial or political gain.

Malware is any code that can be used to steal data, bypass access controls, or cause harm to or compromise a system.

Types of Malware
- Spyware: Designed to track and spy on you, spyware monitors your online activity and can log every key you press on your keyboard, as well as capture almost any of your data, including sensitive personal information such as your online banking details. Spyware does this by modifying the security settings on your devices. It often bundles itself with legitimate software or Trojan horses
- Adware: Adware is often installed with some versions of software and is designed to automatically deliver advertisements to a user, most often on a web browser. You know it when you see it! It’s hard to ignore when you’re faced with constant pop-up ads on your screen. It is common for adware to come with spyware.
- Backdoor: This type of malware is used to gain unauthorized access by bypassing the normal authentication procedures to access a system. As a result, hackers can gain remote access to resources within an application and issue remote system commands. A backdoor works in the background and is difficult to detect.
- Ransomware: This malware is designed to hold a computer system or the data it contains captive until a payment is made. Ransomware usually works by encrypting your data so that you can’t access it. Some versions of ransomware can take advantage of specific system vulnerabilities to lock it down. Ransomware is often spread through phishing emails that encourage you to download a malicious attachment or through a software vulnerability.
- Scareware: This is a type of malware that uses 'scare’ tactics to trick you into taking a specific action. Scareware mainly consists of operating system style windows that pop up to warn you that your system is at risk and needs to run a specific program for it to return to normal operation. If you agree to execute the specific program, your system will become infected with malware.
- Rootkit: This malware is designed to modify the operating system to create a backdoor, which attackers can then use to access your computer remotely. Most rootkits take advantage of software vulnerabilities to gain access to resources that normally shouldn’t be accessible (privilege escalation) and modify system files. Rootkits can also modify system forensics and monitoring tools, making them very hard to detect. In most cases, a computer infected by a rootkit has to be wiped and any required software reinstalled.
- Virus: A virus is a type of computer program that, when executed, replicates and attaches itself to other executable files, such as a document, by inserting its own code. Most viruses require end-user interaction to initiate activation and can be written to act on a specific date or time. Viruses can be relatively harmless, such as those that display a funny image. Or they can be destructive, such as those that modify or delete data. Viruses can also be programmed to mutate in order to avoid detection. Most viruses are spread by USB drives, optical disks, network shares or email.
- Trojan Horse: This malware carries out malicious operations by masking its true intent. It might appear legitimate but is, in fact, very dangerous. Trojans exploit your user privileges and are most often found in image files, audio files or games. Unlike viruses, Trojans do not self-replicate but act as a decoy to sneak malicious software past unsuspecting users.
- Worms: This is a type of malware that replicates itself in order to spread from one computer to another. Unlike a virus, which requires a host program to run, worms can run by themselves. Other than the initial infection of the host, they do not require user participation and can spread very quickly over the network. Worms share similar patterns: They exploit system vulnerabilities, they have a way to propagate themselves, and they all contain malicious code (payload) to cause damage to computer systems or networks. Worms are responsible for some of the most devastating attacks on the Internet. In 2001, the Code Red worm had infected over 300,000 servers in just 19 hours.

Social Engineering
- The manipulation of people into performing actions or divulging confidential information.
- Social engineers often rely on people’s willingness to be helpful, but they also prey on their weaknesses. 
- E.g. an attacker will call an authorized employee with an urgent problem that requires immediate network access and appeal to the employee’s vanity or greed or invoke authority by using name-dropping techniques in order to gain this access.

Pretexting
- This is when an attacker calls an individual and lies to them in an attempt to gain access to privileged data.
- For example, pretending to need a person’s personal or financial data in order to confirm their identity.

Tailgating
- This is when an attacker quickly follows an authorized person into a secure, physical location.

Something for something (quid pro quo)
- This is when an attacker requests personal information from a person in exchange for something, like a free gift.

Denial-of-Service (DoS) 
- a type of network attack that is relatively simple to carry out, even by an unskilled attackers.
- results in some sort of interruption of network service to users, devices or applications.
- Two main types
    - Overwhelming quantity of traffic: This is when a network, host or application is sent an enormous amount of data at a rate which it cannot handle. This causes a slowdown in transmission or response, or the device or service to crash.
    - Maliciously formed packets: A packet is a collection of data that flows between a source and a receiver computer or application over a network, such as the Internet. When a maliciously formatted packet is sent, the receiver will be unable to handle it. For example, if an attacker forwards packets containing errors or improperly formatted packets that cannot be identified by an application, this will cause the receiving device to run very slowly or crash.

Distributed DoS (DDoS) similar to a DoS attack but originates from multiple, coordinated sources.
- An attacker builds a network (botnet) of infected hosts called zombies, which are controlled by handler systems.
- The zombie computers will constantly scan and infect more hosts, creating more and more zombies.
- When ready, the hacker will instruct the handler systems to make the botnet of zombies carry out a DDoS attack

Botnet
- A bot computer is typically infected by visiting an unsafe website or opening an infected email attachment or infected media file. A botnet is a group of bots, connected through the Internet, that can be controlled by a malicious individual or group. It can have tens of thousands, or even hundreds of thousands, of bots that are typically controlled through a command and control server.
- These bots can be activated to distribute malware, launch DDoS attacks, distribute spam email, or execute brute-force password attacks. Cybercriminals will often rent out botnets to third parties for nefarious purposes.
- Many organizations. like Cisco, force network activities through botnet traffic filters to identify any botnet locations.
- The cloud-based Cisco Security Intelligence Operations (SIO) service pushes down updated filters to the firewall that match traffic from new known botnets.
- Alerts go out to Cisco's internal security team to notify them about the infected devices that are generating malicious
traffic so that they can prevent, mitigate and remedy these.

On-path attacks
- On-path attackers intercept or modify communications between two devices, such as a web browser and a web server, either to collect information from or to impersonate one of the devices.
- Man-in-the-middle: A MitM attack happens when a cybercriminal takes control of a device without the user's knowledge. With this level of access, an attacker can intercept and capture user information before it is sent to its intended destination. These types of attacks are often used to steal financial information.
- Man-in-the-mobile: A variation of man-in-middle, MitMo is a type of attack used to take control over a user's mobile device. When infected, the mobile device is instructed to exfiltrate user-sensitive information and send it to the attackers. ZeuS is one example of a malware package with MitMo capabilities. It allows attackers to quietly capture two- step verification SMS messages that are sent to users.

Search Engine Optimization (SEO)
SEO Poisining:
- Attackers take advantage of popular search terms and use SEO to push malicious sites higher up the ranks of search results. This technique is called SEO poisoning.
- The most common goal of SEO poisoning is to increase traffic to malicious sites that may host malware or attempt social engineering.

Password Attacks
- Passowrd spraying
    - This technique attempts to gain access to a system by ‘spraying’ a few commonly used passwords across a large number of accounts. For example, a cybercriminal uses 'Password123' with many usernames before trying again with a second commonly-used password, such as ‘qwerty.’
    - This technique allows the perpetrator to remain undetected as they avoid frequent account lockouts.
- Dictionary attacks
    - A hacker systematically tries every word in a dictionary or a list of commonly used words as a password in an attempt to break into a password-protected account.
- Brute-force attacks
    - The simplest and most commonly used way of gaining access to a password-protected site, brute-force attacks see an attacker using all possible combinations of letters, numbers and symbols in the password space until they get it right.
- Rainbow attacks
    - Passwords in a computer system are not stored as plain text, but as hashed values (numerical values that uniquely identify data). A rainbow table is a large dictionary of precomputed hashes and the passwords from which they were calculated.
    - Unlike a brute-force attack that has to calculate each hash, a rainbow attack compares the hash of a password with those stored in the rainbow table. When an attacker finds a match, they identify the password used to create the hash.
- Traffic interception
    - Plain text or unencrypted passwords can be easily read by other humans and machines by intercepting communications.
    - If you store a password in clear, readable text, anyone who has access to your account or device, whether authorized or unauthorized, can read it.

Advanced Persistent Threats (APTs)
- a multi-phase, long term, stealthy and advanced operation against a specific target. For these reasons, an individual attacker often lacks the skill set, resources or persistence to perform APTs.
- Due to the complexity and the skill level required to carry out such an attack, an APT is usually well-funded and typically targets organizations or nations for business or political reasons.
- Its main purpose is to deploy customized malware on one or more of the target’s systems and remain there undetected.

Hardware Vulnerabilities
- RAM consists of lots of capacitors (a component which can hold an electrical charge) installed very close to one another. However, it was soon discovered that, due to their close proximity, changes applied to one of these capacitors could influence neighbor capacitors. Based on this design flaw, an exploit called Rowhammer was created. By repeatedly accessing (hammering) a row of memory, the Rowhammer exploit triggers electrical interferences that eventually corrupt the data stored inside the RAM.
- Meltdown and Spectre
    - Google security researchers discovered Meltdown and Spectre, two hardware vulnerabilities that affect almost all central processing units (CPUs) released since 1995 within desktops, laptops, servers, smartphones, smart devices and cloud services.
    - Attackers exploiting these vulnerabilities can read all memory from a given system (Meltdown), as well as data handled by other applications (Spectre). The Meltdown and Spectre vulnerability exploitations are referred to as side-channel attacks (information is gained from the implementation of a computer system). They have the ability to compromise large amounts of memory data because the attacks can be run multiple times on a system with very little possibility of a crash or other error.

Software Vulnerabilities
- SYNful Knock vulnerability
    - The SYNful Knock vulnerability allowed attackers to gain control of enterprise-grade routers, such as the legacy Cisco ISR routers, from which they could monitor all network communication and infect other network devices.
    - This vulnerability was introduced into the system when an altered IOS version was installed on the routers. To avoid this, you
    should always verify the integrity of the downloaded IOS image and limit the physical access of such equipment to authorized personnel only.
- Buffer overflow
    - Buffers are memory areas allocated to an application. A vulnerability occurs when data is written beyond the limits of a buffer. By changing data beyond the boundaries of a buffer, the application can access memory allocated to other processes. This can lead to a system crash or data compromise, or provide escalation of privileges.
- Non-validated input
    - Programs often require data input, but this incoming data could have malicious content, designed to force the program to behave in an unintended way.
    - For example, consider a program that receives an image for processing. A malicious user could craft an image file with invalid image dimensions. The maliciously crafted dimensions could force the program to allocate buffers of incorrect and unexpected sizes.
- Race conditions
    - This vulnerability describes a situation where the output of an event depends on ordered or timed outputs. A race condition becomes a source of vulnerability when the required ordered or timed events do not occur in the correct order or at the proper time.
- Weakness in security practices
    - Systems and sensitive data can be protected through techniques such as authentication, authorization and encryption. Developers should stick to using security techniques and libraries that have already been created, tested and verified and should not attempt to create their own security algorithms. These will only likely introduce new vulnerabilities.
- Access control problems
    - Access control is the process of controlling who does what and ranges from managing physical access to equipment to dictating who has access to a resource, such as a file, and what they can do with it, such as read or change the file. Many security vulnerabilities are created by the improper use of access controls.
    - Nearly all access controls and security practices can be overcome if an attacker has physical access to target equipment. For example, no matter the permission settings on a file, a hacker can bypass the operating system and read the data directly off the disk. Therefore, to protect the machine and the data it contains, physical access must be restricted, and encryption techniques must be used to protect data from being stolen or corrupted.

Cryptocurrency
- a digital money that can be used to buy goods and services, using strong encryption techniques to secure online transactions.
- Cryptocurrency owners keep their money in encrypted, virtual ‘wallets.’ When a transaction takes place between the owners of two digital wallets, the details are recorded in a decentralized, electronic ledger or blockchain system. This means it is carried out with a degree of anonymity and is self-managed, with no interference from third parties such as central banks or government entities.
- Approximately every ten minutes, special computers collect data about the latest cryptocurrency transactions, turning them into mathematical puzzles to maintain confidentiality.
- These transactions are then verified through a technical and highly complex process known as ‘mining.’ This step typically involves an army of ‘miners’ working on high-end PCs to solve mathematical puzzles and authenticate transactions.
- Once verified, the ledger is updated and electronically copied and disseminated worldwide to anyone belonging to the blockchain network, effectively completing a transaction.

Cryptojacking
- Cryptojacking is an emerging threat that hides on a user’s computer, mobile phone, tablet, laptop or server, using that machine’s resources to 'mine’ cryptocurrencies without the user's consent or knowledge.
- Many victims of cryptojacking didn’t even know they’d been hacked until it was too late!

Protecting Your Devices and Network

Turn the Firewall On
- You should use at least one type of firewall (either a software firewall or a hardware firewall on a router) to protect your device from unauthorized access. The firewall should be turned on and constantly updated to prevent hackers from accessing your personal or organization data.

Install Antivirus and Antispyware
- You should only ever download software from trusted websites. However, you should always use antivirus software to provide another layer of protection. This software, which often includes antispyware, is designed to scan your computer and incoming email for viruses and delete them. Keeping your software up to date will protect your computer from any new malicious software that emerges.

Managing your Operating System and Browser
- Hackers are always trying to take advantage of vulnerabilities that may exist in your operating system (such as Microsoft Windows or macOS) or web browser (such as Google Chrome or Apple Safari).
- Therefore, to protect your computer and your data, you should set the security settings on your computer and browser to medium level or higher. You should also regularly update your computer’s operating system, including your web browser, and download and install the latest software patches and security updates from the vendors.

Set Up Password Protecting
- All of your computing devices, including PCs, laptops, tablets and smartphones, should be password protected to prevent unauthorized access. Any stored information, especially sensitive or confidential data, should be encrypted. You should only store necessary information on your mobile device, in case it is stolen or lost.
- Remember, if any one of your devices is compromised, the criminals may be able to access all of your data through your cloud storage service provider, such as iCloud or Google Drive.

Wireless Network Security at Home
- Wireless networks allow Wi-Fi enabled devices, such as laptops and tablets, to connect to the network by way of a preset network identifier, known as the service set identifier (SSID). Although a wireless router can be configured so that it doesn’t broadcast the SSID, this should not be considered adequate security for a wireless network.
- Hackers will be aware of the preset SSID and default password. Therefore, these details should be changed to prevent intruders from entering your home wireless network. Furthermore, you should encrypt wireless communication by enabling wireless security and the WPA2 encryption feature on your wireless router. But be aware, even with WPA2 encryption enabled, a wireless network can still be vulnerable.

Public Wifi Risks
- You should always verify that your device isn’t configured with file and media sharing and that it requires user authentication with encryption.
- You should also use an encrypted VPN service to prevent others from intercepting your information (known as ‘eavesdropping’) over a public wireless network. This service gives you secure access to the Internet, by encrypting the connection between your device and the VPN server. Even if hackers intercept a data transmission in an encrypted VPN tunnel, they will not be able to decipher it.

Data Maintenance

How to Encrypt Data
Encrypting File System (EFS) is a Windows feature that can encrypt data. It is directly linked to a specific user account and only the user that encrypts the data will be able to access it after it has been encrypted using EFS.
1. Select one or more files or folders.
2. Right click the selected data and go to ‘Properties.’
3. Find and click ‘Advanced.’
4. Select the ‘Encrypt contents to secure data’ check box.
5. Files and folders that have been encrypted with EFS are displayed in green as shown here.

When you move a file to the recycle bin and delete it permanently, the file is only inaccessible from the operating system. Anyone with the right forensic tools could still recover the file due to a magnetic trace left on the hard drive.

How to Delete Data Permanently 
- To erase data so that it is no longer recoverable, it must be overwritten with ones and zeroes multiple times, using tools specifically designed to do just that. SDelete from Microsoft claims to have the ability to remove sensitive files completely. Shred for Linux and Secure Empty Trash for Mac OS X claim to provide a similar service.
- The only way to be certain that data or files are not recoverable is to physically destroy the hard drive or storage device. Many criminals have taken advantage of files thought to be impenetrable or irrecoverable!
- Don’t forget about data that may be stored online in the cloud. These copies will also need to be deleted.

Who Owns Your Data

Terms of Service agreement: a legally binding contract that governs the rules of the relationship between you, the service provider and others who use the service
- The data use policy outlines how the service provider will collect, use and share your data.
- The privacy settings allow you to control who sees information about you and who can access your profile or account data.
- The security policy outlines what the company is doing to secure the data it obtains from you.