# 🔍 Phishing Email Analysis Lab

## 🎯 Overview
A hands-on phishing investigation lab demonstrating complete email forensic analysis—from header examination and sender reputation checking to IOC extraction and threat intelligence validation. This project simulates real SOC workflow for email-based threat investigation.

## 🚨 Investigation Scenario
**Phishing Campaign:** "Urgent PayPal Account Verification"  
**Target:** Credential harvesting via fake login page  
**Techniques:** Email spoofing, domain impersonation, urgency social engineering

## 🛠️ Analysis Methodology
1. **Email Header Analysis** - SPF, DKIM, DMARC validation
2. **Sender Reputation** - MXToolbox blacklist checking  
3. **IOC Extraction** - URLs, domains, IPs, file hashes
4. **Threat Intelligence** - VirusTotal, URLScan, AbuseIPDB
5. **Reporting** - Executive and technical documentation

## 📁 Repository Structure
```
phishing-email-analysis-lab/
├── README.md
├── samples/
│   ├── phishing-sample.eml
│   └── phishing-sample.txt
├── analysis/
│   ├── email-headers.txt
│   ├── iocs.txt
│   └── mxtoolbox-results.txt
├── screenshots/
│   ├── mxtoolbox-analysis.png
│   ├── virustotal-results.png
│   └── email-header-view.png
├── reports/
│   └── PHISHING-INVESTIGATION-2024-001.md
└── tools/
    └── header-analyzer.py
```

## 🚀 Quick Start
1. **Examine** `samples/phishing-sample.eml`
2. **Review** `analysis/` folder for investigation artifacts
3. **Follow** the investigation in `reports/PHISHING-INVESTIGATION-2024-001.md`

## 🔧 Tools Used
- **Email Analysis:** MXToolbox Header Analyzer, MessageHeader
- **Threat Intel:** VirusTotal, URLScan.io, AbuseIPDB
- **Forensics:** CyberChef, Hybrid Analysis (optional)

## 👨‍💻 Author
**Renaldi** | SOC & Cloud Security Analyst  
[LinkedIn](https://linkedin.com/in/renaldi-tan) | [Main Portfolio](https://github.com/SilentVeil/Cloud-Security-SOC-Analyst-Portfolio)

---
*"Phishing remains the #1 initial access vector—detecting it quickly is the SOC's first line of defense."*
