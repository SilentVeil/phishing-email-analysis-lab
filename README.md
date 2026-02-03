# 🔍 Phishing Email Analysis Lab

## 🎯 Overview
A hands-on phishing investigation lab demonstrating complete email forensic analysis—from header examination and sender reputation checking to IOC extraction and threat intelligence validation. This project simulates real SOC workflow for email-based threat investigation using actual malicious indicators.

## 🚨 Investigation Scenario
**Phishing Campaign:** "Urgent PayPal Account Verification"  
**Target:** Credential harvesting via fake login page  
**Techniques:** Email spoofing, domain impersonation, urgency social engineering  
**Real IOCs:** vetscommunityconnections.org, 143.14.107.169

## 🛠️ Analysis Methodology
1. **Email Header Analysis** - SPF, DKIM, DMARC validation via MXToolbox
2. **Sender Reputation** - Blacklist checking and infrastructure analysis  
3. **IOC Extraction** - URLs, domains, IPs from phishing email
4. **Threat Intelligence** - VirusTotal, AbuseIPDB validation
5. **Reporting** - Executive and technical documentation with MITRE ATT&CK mapping

## 📁 Repository Structure
```
phishing-email-analysis-lab/
├── README.md
├── samples/
│ └── phishing-sample.eml
├── analysis/
│ ├── email-headers.txt
│ ├── iocs.txt
│ └── mxtoolbox-results.txt
├── screenshots/
│ ├── mxtoolbox-analysis.png
│ ├── virustotal-ip-detection.png
│ ├── virustotal-domain.png
│ └── abuseipdb-results.png
├── reports/
│ └── PHISHING-INVESTIGATION-2024-001.md
```


## 🚀 Quick Start
1. **Review** the phishing sample: `samples/phishing-sample.eml`
2. **Examine** investigation artifacts in `analysis/` folder
3. **Follow** the complete investigation in `reports/PHISHING-INVESTIGATION-2024-001.md`
4. **Validate** IOCs using the provided threat intelligence screenshots

## 🔧 Tools Used
- **Email Header Analysis:** MXToolbox Email Header Analyzer
- **Threat Intelligence:** VirusTotal, AbuseIPDB
- **IOC Sources:** AlienVault OTX
- **Documentation:** Markdown, MITRE ATT&CK Framework
- **Platform:** GitHub (version control & portfolio hosting)

## 📊 Key Findings
- **SPF/DKIM/DMARC Failures:** Email confirmed as spoofed
- **Malicious Infrastructure:** 9/94 security vendors flag IP as malicious
- **Bulletproof Hosting:** CYBERVERSE LLC provider in Tokyo, Japan
- **Recent Deployment:** No historical abuse reports (new infrastructure)

## 👨‍💻 Author
**Renaldi** | SOC & Cloud Security Analyst  
[LinkedIn](https://linkedin.com/in/renaldi-tan) | [Main Portfolio](https://github.com/SilentVeil/Cloud-Security-SOC-Analyst-Portfolio)

---
*"Phishing remains the #1 initial access vector—detecting it quickly is the SOC's first line of defense."*
