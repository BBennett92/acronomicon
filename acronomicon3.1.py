import tkinter as tk


# create a list of dictionaries containing the questions and answer choices
quiz_questions = [
    {
    "question": "What does DLP stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "A. Data Loss Prevention"
},
{
    "question": "What does WAF stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "B. Web Application Firewall"
},
{
    "question": "What does NGFW stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "C. Next-Generation Firewall"
},
{
    "question": "What does ZTNA stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "D. Zero Trust Network Access"
},
{
    "question": "What does SD-WAN stand for?",
    "choices": ["A. Software-Defined Wide Area Network", "B. Security Orchestration, Automation, and Response", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "A. Software-Defined Wide Area Network"
},
{
    "question": "What does SASE stand for?",
    "choices": ["A. Software-Defined Wide Area Network", "B. Security Orchestration, Automation, and Response", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "B. Security Orchestration, Automation, and Response"
},
{
    "question": "What does SSE stand for?",
    "choices": ["A. Security Service Edge", "B. User and Entity Behavior Analytics", "C. Data Loss Prevention", "D. Web Application Firewall"],
    "answer": "A. Security Service Edge"
},
{
    "question": "What does XDR stand for?",
    "choices": ["A. Extended Detection and Response", "B. Managed Detection and Response", "C. Security Orchestration, Automation, and Response", "D. Cloud Access Security Broker"],
    "answer": "A. Extended Detection and Response"
},
{
    "question": "What does MDR stand for?",
    "choices": ["A. Extended Detection and Response", "B. Managed Detection and Response", "C. Security Orchestration, Automation, and Response", "D. Cloud Access Security Broker"],
    "answer": "B. Managed Detection and Response"
},
{
    "question": "What does SOC stand for?",
    "choices": ["A. Security Operations Center", "B. Security Orchestration, Automation, and Response", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "A. Security Operations Center"
},
    {
    "question": "What does DLP stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "A. Data Loss Prevention"
},
{
    "question": "What does WAF stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "B. Web Application Firewall"
},
{
    "question": "What does NGFW stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "C. Next-Generation Firewall"
},
{
    "question": "What does ZTNA stand for?",
    "choices": ["A. Data Loss Prevention", "B. Web Application Firewall", "C. Next-Generation Firewall", "D. Zero Trust Network Access"],
    "answer": "D. Zero Trust Network Access"
},
{
    "question": "What does SD-WAN stand for?",
    "choices": ["A. Software-Defined Wide Area Network", "B. Security Orchestration, Automation, and Response", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "A. Software-Defined Wide Area Network"
},
{
    "question": "What does SASE stand for?",
    "choices": ["A. Software-Defined Wide Area Network", "B. Security Orchestration, Automation, and Response", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "B. Security Orchestration, Automation, and Response"
},
{
    "question": "What does SSE stand for?",
    "choices": ["A. Security Service Edge", "B. User and Entity Behavior Analytics", "C. Data Loss Prevention", "D. Web Application Firewall"],
    "answer": "A. Security Service Edge"
},
{
    "question": "What does XDR stand for?",
    "choices": ["A. Extended Detection and Response", "B. Managed Detection and Response", "C. Security Orchestration, Automation, and Response", "D. Cloud Access Security Broker"],
    "answer": "A. Extended Detection and Response"
},
{
    "question": "What does MDR stand for?",
    "choices": ["A. Extended Detection and Response", "B. Managed Detection and Response", "C. Security Orchestration, Automation, and Response", "D. Cloud Access Security Broker"],
    "answer": "B. Managed Detection and Response"
},
{
    "question": "What does SOC stand for?",
    "choices": ["A. Security Orchestration Automation and Response", "B. Security Operations Center", "C. Cloud Access Security Broker", "D. Firewall as a Service"],
    "answer": "B. Security Operations Center"
},
    {
        "question": "What does XDR stand for?",
        "choices": ["A. Extended Detection and Response", "B. Extended Detection and Response System", "C. Extended Detection and Response Center", "D. Extended Detection and Response Service"],
        "answer": "A. Extended Detection and Response"
    },
    {
        "question": "What does OTP stand for?",
        "choices": ["A. One-Time Password", "B. One-Time Password System", "C. One-Time Password Center", "D. One-Time Password Service"],
        "answer": "A. One-Time Password"
    },
    {
        "question": "What does IDS stand for?",
        "choices": ["A. Intrusion Detection System", "B. Intrusion Detection System System", "C. Intrusion Detection System Center", "D. Intrusion Detection System Service"],
        "answer": "A. Intrusion Detection System"
    },
    {
        "question": "What does IPS stand for?",
        "choices": ["A. Intrusion Prevention System", "B. Intrusion Prevention System System", "C. Intrusion Prevention System Center", "D. Intrusion Prevention System Service"],
        "answer": "A. Intrusion Prevention System"
    },
    {
        "question": "What does SIEM stand for?",
        "choices": ["A. Security Information and Event Management", "B. Security Information and Event Management System", "C. Security Information and Event Management Center", "D. Security Information and Event Management Service"],
        "answer": "A. Security Information and Event Management"
    },
    {
        "question": "What does SOAR stand for?",
        "choices": ["A. Security Orchestration, Automation, and Response", "B. Security Orchestration, Automation, and Response System", "C. Security Orchestration, Automation, and Response Center", "D. Security Orchestration, Automation, and Response Service"],
        "answer": "A. Security Orchestration, Automation, and Response"
    },
    {
        "question": "What does CASB stand for?",
        "choices": ["A. Cloud Access Security Broker", "B. Cloud Access Security Broker System", "C. Cloud Access Security Broker Center", "D. Cloud Access Security Broker Service"],
        "answer": "A. Cloud Access Security Broker"
    },
    {
        "question": "What does FWaaS stand for?",
        "choices": ["A. Firewall as a Service", "B. Firewall as a Service System", "C. Firewall as a Service Center", "D. Firewall as a Service Service"],
        "answer": "A. Firewall as a Service"
    },
    {
        "question": "What does UEBA stand for?",
        "choices": ["A. User and Entity Behavior Analytics", "B. User and Entity Behavior Analytics System", "C. User and Entity Behavior Analytics Center", "D. User and Entity Behavior Analytics Service"],
        "answer": "A. User and Entity Behavior Analytics"
    },
    {
        "question": "What does APT stand for?",
        "choices": ["A. Advanced Persistent Threat", "B. Advanced Persistent Threat System", "C. Advanced Persistent Threat Center", "D. Advanced Persistent Threat Service"],
        "answer": "A. Advanced Persistent Threat"
    },
    {
        "question": "What does RAT stand for?",
        "choices": ["A. Remote Access Trojan", "B. Remote Access Trojan System", "C. Remote Access Trojan Center", "D. Remote Access Trojan Service"],
        "answer": "A. Remote Access Trojan"
    },
    {
        "question": "What does DDoS stand for?",
        "choices": ["A. Distributed Denial-of-Service", "B. Distributed Denial-of-Service System", "C. Distributed Denial-of-Service Center", "D. Distributed Denial-of-Service Service"],
        "answer": "A. Distributed Denial-of-Service"
    },
    {
        "question": "What does SQL injection stand for?",
        "choices": ["A. SQL injection", "B. SQL injection System", "C. SQL injection Center", "D. SQL injection Service"],
        "answer": "A. SQL injection"
    },
    {
        "question": "What does XSS stand for?",
        "choices": ["A. Cross-Site Scripting", "B. Cross-Site Scripting System", "C. Cross-Site Scripting Center", "D. Cross-Site Scripting Service"],
        "answer": "A. Cross-Site Scripting"
    },
    {
        "question": "What does phishing stand for?",
        "choices": ["A. Phishing", "B. Phishing System", "C. Phishing Center", "D. Phishing Service"],
        "answer": "A. Phishing"
    },
    {
        "question": "What does malware stand for?",
        "choices": ["A. Malicious software", "B. Malicious software System", "C. Malicious software Center", "D. Malicious software Service"],
        "answer": "A. Malicious software"
    },
    {
        "question": "What does ransomware stand for?",
        "choices": ["A. Ransomware", "B. Ransomware System", "C. Ransomware Center", "D. Ransomware Service"],
        "answer": "A. Ransomware"
    },
    {
        "question": "What does MFA stand for?",
        "choices": ["A. Multi-Factor Authentication", "B. Multi-Factor Authentication System", "C. Multi-Factor Authentication Center", "D. Multi-Factor Authentication Service"],
        "answer": "A. Multi-Factor Authentication"
    },
    {
        "question": "What does SSO stand for?",
        "choices": ["A. Single Sign-On", "B. Single Sign-On System", "C. Single Sign-On Center", "D. Single Sign-On Service"],
        "answer": "A. Single Sign-On"
    },
    {
        "question": "What does IAM stand for?",
        "choices": ["A. Identity and Access Management", "B. Identity and Access Management System", "C. Identity and Access Management Center", "D. Identity and Access Management Service"],
        "answer": "A. Identity and Access Management"
    },
    {
        "question": "What does GRC stand for?",
        "choices": ["A. Governance, Risk, and Compliance", "B. Governance, Risk, and Compliance System", "C. Governance, Risk, and Compliance Center", "D. Governance, Risk, and Compliance Service"],
        "answer": "A. Governance, Risk, and Compliance"
    },
    {
        "question": "What does BCP stand for?",
        "choices": ["A. Business Continuity Planning", "B. Business Continuity Planning System", "C. Business Continuity Planning Center", "D. Business Continuity Planning Service"],
        "answer": "A. Business Continuity Planning"
    },
    {
        "question": "What does DRP stand for?",
        "choices": ["A. Disaster Recovery Planning", "B. Disaster Recovery Planning System", "C. Disaster Recovery Planning Center", "D. Disaster Recovery Planning Service"],
        "answer": "A. Disaster Recovery Planning"
    },
    {
        "question": "What does IR stand for?",
        "choices": ["A. Incident Response", "B. Incident Response System", "C. Incident Response Center", "D. Incident Response Service"],
        "answer": "A. Incident Response"
    },
    {
        "question": "What does DNS stand for?",
        "choices": ["A. Domain Name System", "B. Domain Name System System", "C. Domain Name System Center", "D. Domain Name System Service"],
        "answer": "A. Domain Name System"
    },
    {
        "question": "What does DHCP stand for?",
        "choices": ["A. Dynamic Host Configuration Protocol", "B. Dynamic Host Configuration Protocol System", "C. Dynamic Host Configuration Protocol Center", "D. Dynamic Host Configuration Protocol Service"],
        "answer": "A. Dynamic Host Configuration Protocol"
    },
    {
        "question": "What does IP stand for?",
        "choices": ["A. Internet Protocol", "B. Internet Protocol System", "C. Internet Protocol Center", "D. Internet Protocol Service"],
        "answer": "A. Internet Protocol"
    },
    {
        "question": "What does TCP stand for?",
        "choices": ["A. Transmission Control Protocol", "B. Transmission Control Protocol System", "C. Transmission Control Protocol Center", "D. Transmission Control Protocol Service"],
        "answer": "A. Transmission Control Protocol"
    },
    {
        "question": "What does UDP stand for?",
        "choices": ["A. User Datagram Protocol", "B. User Datagram Protocol System", "C. User Datagram Protocol Center", "D. User Datagram Protocol Service"],
        "answer": "A. User Datagram Protocol"
    },
    {
        "question": "What does HTTP stand for?",
        "choices": ["A. Hypertext Transfer Protocol", "B. Hypertext Transfer Protocol System", "C. Hypertext Transfer Protocol Center", "D. Hypertext Transfer Protocol Service"],
        "answer": "A. Hypertext Transfer Protocol"
    },
    {
        "question": "What does HTTPS stand for?",
        "choices": ["A. Hypertext Transfer Protocol Secure", "B. Hypertext Transfer Protocol Secure System", "C. Hypertext Transfer Protocol Secure Center", "D. Hypertext Transfer Protocol Secure Service"],
        "answer": "A. Hypertext Transfer Protocol Secure"
    },
    {
        "question": "What does CVE stand for?",
        "choices": ["A. Common Vulnerabilities and Exposures", "B. Common Vulnerabilities and Exposure System", "C. Common Vulnerabilities and Exposure Center", "D. Common Vulnerabilities and Exposure Service"],
        "answer": "A. Common Vulnerabilities and Exposures"
    },
    {
        "question": "What does CWE stand for?",
        "choices": ["A. Common Weakness Enumeration", "B. Common Weakness Enumeration System", "C. Common Weakness Enumeration Center", "D. Common Weakness Enumeration Service"],
        "answer": "A. Common Weakness Enumeration"
    },
    {
        "question": "What does OWASP stand for?",
        "choices": ["A. Open Web Application Security Project", "B. Open Web Application Security Projects", "C. Open Web Application Security Project System", "D. Open Web Application Security Project Service"],
        "answer": "A. Open Web Application Security Project"
    },
    {
        "question": "What is the OWASP Top 10?",
        "choices": ["A. The Open Web Application Security Project Top 10", "B. The Open Web Application Security Project Top 10s", "C. The Open Web Application Security Project Top 10 System", "D. The Open Web Application Security Project Top 10 Service"],
        "answer": "A. The Open Web Application Security Project Top 10"
    },
    {
        "question": "What does PCI DSS stand for?",
        "choices": ["A. Payment Card Industry Data Security Standard", "B. Payment Card Industry Data Security Standards", "C. Payment Card Industry Data Security Standard System", "D. Payment Card Industry Data Security Standard Service"],
        "answer": "A. Payment Card Industry Data Security Standard"
    },
    {
        "question": "What is the NIST Cybersecurity Framework?",
        "choices": ["A. The National Institute of Standards and Technology Cybersecurity Framework", "B. The National Institute of Standards and Technology Cybersecurity Frameworks", "C. The National Institute of Standards and Technology Cybersecurity Framework System", "D. The National Institute of Standards and Technology Cybersecurity Framework Service"],
        "answer": "A. The National Institute of Standards and Technology Cybersecurity Framework"
    },
    {
        "question": "What is ISO 27001?",
        "choices": ["A. International Organization for Standardization 27001", "B. International Organization for Standardization 27001s", "C. International Organization for Standardization 27001 System", "D. International Organization for Standardization 27001 Service"],
        "answer": "A. International Organization for Standardization 27001"
    },
    {
        "question": "What does SOC stand for?",
        "choices": ["A. Security Operations Center", "B. Security Operations Center System", "C. Security Operations Center Center", "D. Security Operations Center Service"],
        "answer": "A. Security Operations Center"
    },
    {
        "question": "What does CSIRT stand for?",
        "choices": ["A. Computer Security Incident Response Team", "B. Computer Security Incident Response Teams", "C. Computer Security Incident Response Team System", "D. Computer Security Incident Response Team Service"],
        "answer": "A. Computer Security Incident Response Team"
    },
    {
        "question": "What does CERT stand for?",
        "choices": ["A. Computer Emergency Response Team", "B. Computer Emergency Response Teams", "C. Computer Emergency Response Team System", "D. Computer Emergency Response Team Service"],
        "answer": "A. Computer Emergency Response Team"
    },
    {
        "question": "What does TTP stand for?",
        "choices": ["A. Technique, Tactics, and Procedures", "B. Technique, Tactics, and Processes", "C. Technique, Tactics, and Policies", "D. Technique, Tactics, and Proofs"],
        "answer": "A. Technique, Tactics, and Procedures"
    },
    {
        "question": "What does MITRE stand for?",
        "choices": ["A. Mitre Corporation", "B. Mitre Institute", "C. Mitre Systems", "D. Mitre Services"],
        "answer": "A. Mitre Corporation"
    },
    {
        "question": "What does ATT&CK stand for?",
        "choices": ["A. Adversarial Tactics, Techniques, and Common Knowledge", "B. Adversarial Tactics, Techniques, and Common Knowledge System", "C. Adversarial Tactics, Techniques, and Common Knowledge Center", "D. Adversarial Tactics, Techniques, and Common Knowledge Service"],
        "answer": "A. Adversarial Tactics, Techniques, and Common Knowledge"
    },
    {
        "question": "What does SCADA stand for?",
        "choices": ["A. Supervisory Control and Data Acquisition", "B. Supervisory Control and Data Acquisition System", "C. Supervisory Control and Data Acquisition Center", "D. Supervisory Control and Data Acquisition Service"],
        "answer": "A. Supervisory Control and Data Acquisition"
    },
    {
        "question": "What does ICS stand for?",
        "choices": ["A. Industrial Control System", "B. Industrial Control Systems", "C. Industrial Control Security", "D. Industrial Control System Security"],
        "answer": "A. Industrial Control System"
    },
    {
        "question": "What does OT stand for?",
        "choices": ["A. Operational Technology", "B. Operational Technologies", "C. Operational Technology Security", "D. Operational Technology System Security"],
        "answer": "A. Operational Technology"
    },
    {
        "question": "What does APT stand for?",
        "choices": ["A. Advanced Persistent Threat", "B. Advanced Persistent Attack", "C. Advanced Persistent Threat System", "D. Advanced Persistent Attack System"],
        "answer": "A. Advanced Persistent Threat"
    },
    {
        "question": "What does CISO stand for?",
        "choices": ["A. Chief Information Security Officer", "B. Chief Information Security Operations", "C. Chief Information Security Officer System", "D. Chief Information Security Officer Service"],
        "answer": "A. Chief Information Security Officer"
    },
    {
        "question": "What does DLP stand for?",
        "choices": ["A. Data Loss Prevention", "B. Data Loss Protection", "C. Data Loss Prevention System", "D. Data Loss Protection Service"],
        "answer": "A. Data Loss Prevention"
    },
    {
        "question": "What does IAM stand for?",
        "choices": ["A. Identity and Access Management", "B. Identity and Authentication Management", "C. Identity and Authorization Management", "D. Identity and Authorization System"],
        "answer": "A. Identity and Access Management"
    },
    {
        "question": "What does MFA stand for?",
        "choices": ["A. Multi-Factor Authentication", "B. Multi-Factor Authorization", "C. Multi-Factor Authentication System", "D. Multi-Factor Authentication Service"],
        "answer": "A. Multi-Factor Authentication"
    },
    {
        "question": "What does MDM stand for?",
        "choices": ["A. Mobile Device Management", "B. Mobile Device Management System", "C. Mobile Device Management Center", "D. Mobile Device Management Service"],
        "answer": "A. Mobile Device Management"
    },
    {
        "question": "What does MDR stand for?",
        "choices": ["A. Managed Detection and Response", "B. Managed Detection and Response System", "C. Managed Detection and Response Center", "D. Managed Detection and Response Service"],
        "answer": "A. Managed Detection and Response"
    },
    {
        "question": "What does Kerberos stand for?",
        "choices": ["A. Key Distribution Center", "B. Key Distribution System", "C. Key Distribution Service", "D. Key Distribution Security"],
        "answer": "A. Key Distribution Center"
    },
    {
        "question": "What does SIEM stand for?",
        "choices": ["A. Security Information and Event Management", "B. Security Information and Event Management System", "C. Security Information and Event Management Center", "D. Security Information and Event Management Service"],
        "answer": "A. Security Information and Event Management"
    },
    {
        "question": "What does SOAR stand for?",
        "choices": ["A. Security Orchestration, Automation, and Response", "B. Security Orchestration, Automation, and Reporting", "C. Security Orchestration, Automation, and Remediation", "D. Security Orchestration, Automation, and Analysis"],
        "answer": "A. Security Orchestration, Automation, and Response"
    },
    {
        "question": "What does UEBA stand for?",
        "choices": ["A. User and Entity Behavior Analytics", "B. User and Entity Behavior Analysis", "C. User and Entity Behavior Authentication", "D. User and Entity Behavior Authorization"],
        "answer": "A. User and Entity Behavior Analytics"
    },
    {
        "question": "What does XDR stand for?",
        "choices": ["A. Extended Detection and Response", "B. Extended Detection and Response System", "C. Extended Detection and Response Center", "D. Extended Detection and Response Service"],
        "answer": "A. Extended Detection and Response"
    },
    {
        "question": "What does SHA-3 stand for?",
        "choices": ["A. Secure Hash Algorithm 3", "B. Secure Hash Algorithm 4", "C. Secure Hash Algorithm 5", "D. Secure Hash Algorithm 6"],
        "answer": "A. Secure Hash Algorithm 3"
    },
    {
        "question": "What does HMAC stand for?",
        "choices": ["A. Hash-based Message Authentication Code", "B. Hash-based Message Authentication Control", "C. Hash-based Message Authentication Code 2", "D. Hash-based Message Authentication Code 3"],
        "answer": "A. Hash-based Message Authentication Code"
    },
    {
        "question": "What does AES stand for?",
        "choices": ["A. Advanced Encryption Standard", "B. Advanced Encryption System", "C. Advanced Encryption Service", "D. Advanced Encryption Software"],
        "answer": "A. Advanced Encryption Standard"
    },
    {
        "question": "What does RSA stand for?",
        "choices": ["A. Rivest-Shamir-Adleman", "B. Rivest-Shamir-Adleman Algorithm", "C. Rivest-Shamir-Adleman Protocol", "D. Rivest-Shamir-Adleman System"],
        "answer": "A. Rivest-Shamir-Adleman"
    },
    {
        "question": "What does DSA stand for?",
        "choices": ["A. Digital Signature Algorithm", "B. Digital Signature Algorithms", "C. Digital Signature Authentication", "D. Digital Signature Authorization"],
        "answer": "A. Digital Signature Algorithm"
    },
    {
        "question": "What does PGP stand for?",
        "choices": ["A. Pretty Good Privacy", "B. Pretty Good Protection", "C. Pretty Good Password", "D. Pretty Good Protocol"],
        "answer": "A. Pretty Good Privacy"
    },
    {
        "question": "What does GPG stand for?",
        "choices": ["A. GNU Privacy Guard", "B. GNU Privacy Gateway", "C. GNU Privacy Guard 2", "D. GNU Privacy Guard 3"],
        "answer": "A. GNU Privacy Guard"
    },
    {
        "question": "What does SHA stand for?",
        "choices": ["A. Secure Hash Algorithm", "B. Secure Hash Algorithms", "C. Secure Hashing Algorithm", "D. Secure Hashing Algorithms"],
        "answer": "A. Secure Hash Algorithm"
    },
    {
        "question": "What does MD5 stand for?",
        "choices": ["A. Message Digest 5", "B. Message Digest 6", "C. Message Digest 7", "D. Message Digest 8"],
        "answer": "A. Message Digest 5"
    },
    {
        "question": "What does SHA-2 stand for?",
        "choices": ["A. Secure Hash Algorithm 2", "B. Secure Hash Algorithm 3", "C. Secure Hash Algorithm 4", "D. Secure Hash Algorithm 5"],
        "answer": "A. Secure Hash Algorithm 2"
    },
    {
        "question": "What does SFTP stand for?",
        "choices": ["A. Secure File Transfer Protocol", "B. Secure File Transfer Proxy", "C. Secure File Transfer System", "D. Secure File Transfer Service"],
        "answer": "A. Secure File Transfer Protocol"
    },
    {
        "question": "What does FTPS stand for?",
        "choices": ["A. File Transfer Protocol Secure", "B. File Transfer Protocol Security", "C. File Transfer Protocol 2 Secure", "D. File Transfer Protocol 3 Secure"],
        "answer": "A. File Transfer Protocol Secure"
    },
    {
        "question": "What does IMAP stand for?",
        "choices": ["A. Internet Message Access Protocol", "B. Internet Mail Access Protocol", "C. Internet Message Protocol", "D. Internet Mail Protocol"],
        "answer": "A. Internet Message Access Protocol"
    },
    {
        "question": "What does POP3 stand for?",
        "choices": ["A. Post Office Protocol 3", "B. Post Office Protocol 2", "C. Post Office Protocol", "D. Post Office Protocol 1"],
        "answer": "A. Post Office Protocol 3"
    },
    {
        "question": "What does MIME stand for?",
        "choices": ["A. Multipurpose Internet Mail Extensions", "B. Multipurpose Internet Mail Extensible", "C. Multipurpose Internet Mail Exchange", "D. Multipurpose Internet Mail Extension"],
        "answer": "A. Multipurpose Internet Mail Extensions"
    },
    {
        "question": "What does SQL stand for?",
        "choices": ["A. Structured Query Language", "B. Standard Query Language", "C. Sequential Query Language", "D. Secure Query Language"],
        "answer": "A. Structured Query Language"
    },
    {
        "question": "What does MITM stand for?",
        "choices": ["A. Man-in-the-Middle Attack", "B. Man-in-the-Middle Authentication", "C. Man-in-the-Middle Encryption", "D. Man-in-the-Middle Security"],
        "answer": "A. Man-in-the-Middle Attack"
    },
    {
        "question": "What does DNS stand for?",
        "choices": ["A. Domain Name System", "B. Domain Name Server", "C. Domain Name Service", "D. Domain Name Security"],
        "answer": "A. Domain Name System"
    },
    {
        "question": "What does IP stand for?",
        "choices": ["A. Internet Protocol", "B. Internet Port", "C. Internet Protocol Address", "D. Internet Protocol Security"],
        "answer": "A. Internet Protocol"
    },
    {
        "question": "What does HTTP stand for?",
        "choices": ["A. Hypertext Transfer Protocol", "B. Hypertext Transfer Protocol Secure", "C. Hypertext Transfer Protocol 2", "D. Hypertext Transfer Protocol 3"],
        "answer": "A. Hypertext Transfer Protocol"
    },
    {
        "question": "What does SSL stand for?",
        "choices": ["A. Secure Socket Layer", "B. Secure System Logon", "C. Secure System Layer", "D. Security System Log"],
        "answer": "A. Secure Socket Layer"
    },
    {
        "question": "What does VPN stand for?",
        "choices": ["A. Virtual Private Network", "B. Virtual Public Network", "C. Very Private Network", "D. Very Public Network"],
        "answer": "A. Virtual Private Network"
    },
    {
        "question": "What does AES stand for?",
        "choices": ["A. Advanced Encryption System", "B. Advanced Encryption Standard", "C. Advanced Encryption Service", "D. Advanced Encryption Software"],
        "answer": "B. Advanced Encryption Standard"
    },
    {
        "question": "What does XSS stand for?",
        "choices": ["A. Cross-Site Security", "B. Cross-Site Scripting", "C. Cross-System Scripting", "D. Cross-System Security"],
        "answer": "B. Cross-Site Scripting"
    },
    {
        "question": "What does CSRF stand for?",
        "choices": ["A. Cross-Site Request Forgery", "B. Cross-Site Resource Forgery", "C. Cross-System Request Forgery", "D. Cross-System Resource Forgery"],
        "answer": "A. Cross-Site Request Forgery"
    },
    {
        "question": "What does CIA stand for?",
        "choices": ["A. Central Intelligence Agency", "B. Computer Incident Advisory Capability", "C. Cybersecurity and Infrastructure Agency", "D. Confidentiality, Integrity, Availability"],
        "answer": "D. Confidentiality, Integrity, Availability"
    },
    {
        "question": "What does IDS stand for?",
        "choices": ["A. Internet Data Server", "B. Intrusion Detection System", "C. Information Delivery System", "D. Internal Database Service"],
        "answer": "B. Intrusion Detection System"
    },
    {
        "question": "What does DDoS stand for?",
        "choices": ["A. Distributed Domain Name System", "B. Dynamic Domain Name Service", "C. Distributed Denial of Service", "D. Dynamic Denial of Service"],
        "answer": "C. Distributed Denial of Service"
    }
]

# set up the tkinter GUI
root = tk.Tk()
root.title("ACRONOMICON - Cybersecurity Acronym Quiz")

# create variables to track the current question number and the user's score
current_question = 0
score = 0

# define functions for checking the user's answer and updating the GUI
def check_answer(user_answer):
    global current_question, score
    if user_answer == quiz_questions[current_question]["answer"]:
        label_result.config(text="CORRECT!")
        score += 1
    else:
        label_result.config(text="INCORRECT!")
    button_skip.config(state="disabled")
    button_next.config(state="normal")

def skip_question():
    global current_question
    current_question += 1
    update_question()

def next_question():
    global current_question
    current_question += 1
    update_question()

def update_question():
    global current_question
    if current_question < len(quiz_questions):
        # update the question and answer choices
        label_question.config(text=quiz_questions[current_question]["question"])
        for i in range(4):
            buttons[i].config(text=quiz_questions[current_question]["choices"][i])
        # reset the result label and button states
        label_result.config(text="")
        button_skip.config(state="normal")
        button_next.config(state="disabled")
    else:
        # show the user's score when all questions have been answered
        label_question.config(text=f"You got {score} out of {len(quiz_questions)} questions correct!")

# create the question label and answer choice buttons
label_question = tk.Label(root, text="")
label_question.pack(pady=10)

buttons = []
for i in range(4):
    button = tk.Button(root, text="", width=50, command=lambda user_answer=i: check_answer(quiz_questions[current_question]["choices"][user_answer]))
    button.pack(pady=5)
    buttons.append(button)

# create the result label and skip/next buttons
label_result = tk.Label(root, text="")
label_result.pack(pady=10)

button_skip = tk.Button(root, text="Skip", width=10, command=skip_question, state="disabled")
button_skip.pack(side="left", padx=10)

button_next = tk.Button(root, text="Next", width=10, command=next_question, state="disabled")
button_next.pack(side="right", padx=10)

# start the quiz with the first question
update_question()

root.mainloop()