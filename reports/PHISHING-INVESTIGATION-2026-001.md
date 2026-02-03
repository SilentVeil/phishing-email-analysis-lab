# 🔍 Phishing Investigation Report - Case #2026-001

## 📋 Executive Summary
**Date:** 2026-01-30  
**Threat:** PayPal credential phishing campaign  
**Target:** Organization employees  
**IOCs:** vetscommunityconnections.org, 143.14.107.169  
**Status:** Contained, IOCs blocked, users alerted

## 🎯 Email Details
- **Subject:** Urgent: Your PayPal Account Has Been Limited
- **Sender:** security@vetscommunityconnections.org (spoofed PayPal)
- **Recipient:** victim@company.com
- **Technique:** Brand impersonation + urgency social engineering
- **Goal:** Credential harvesting via fake login page

## 🔧 Technical Analysis

### 1. Email Header Forensics
**MXToolbox Analysis Results:**
- SPF: FAIL ❌ (domain does not authorize sending IP)
- DKIM: NOT SIGNED ❌
- DMARC: FAIL ❌ (policy: REJECT)
- IP Reputation: 143.14.107.169 - Blacklisted

![Header Analysis](../screenshots/mxtoolbox-analysis.png)

### 2. IOC Identification & Validation
**Malicious Domain:** vetscommunityconnections.org
- Source: AlienVault OTX threat feed
- Age: Recently registered (highly suspicious)
- Purpose: Phishing landing page hosting

**Malicious IP:** 143.14.107.169
- Blacklist status: Listed in 3+ security feeds
- Associated campaigns: Multiple phishing operations
- Geographic location: High-risk region

**Phishing URL:** http://vetscommunityconnections.org/phish.html
- Type: Credential harvesting form
- SSL: None (HTTP only - low sophistication)
- Content: PayPal login page imitation

### 3. Threat Intelligence Correlation
**VirusTotal Detection:**
- Domain: vetscommunityconnections.org → 8/94 vendors flag as malicious
- IP: 143.14.107.169 → 12/89 vendors flag as malicious
- Categories: Phishing, Fraud, Social Engineering

**AbuseIPDB Results:**
- Confidence Score: 85% (High confidence malicious)
- Total Reports: 22 abuse reports
- Last Report: Within 7 days

![Threat Intel Validation](../screenshots/virustotal-results.png)

## 🛡️ Response Actions

### Immediate Containment:
1. **Block IOCs:**
   - Domain: vetscommunityconnections.org (firewall, DNS, proxy)
   - IP: 143.14.107.169 (firewall, IDS/IPS)
   - URL: http://vetscommunityconnections.org/phish.html (web filter)

2. **User Protection:**
   - Alert sent to all employees
   - Instructions to report similar emails
   - Credential reset for any users who clicked link

3. **Threat Hunting:**
   - Search logs for connections to malicious IP
   - Check for successful credential submissions
   - Review email gateway for similar patterns

### Preventive Measures:
1. Enhance email filtering rules for typosquatting domains
2. Implement stricter DMARC policies (p=reject)
3. User awareness training on phishing indicators
4. Deploy URL rewriting in email gateway

## 📊 MITRE ATT&CK Mapping
| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Phishing | T1566.002 | Spearphishing Link |
| Credential Access | Credentials from Password Stores | T1555.003 | Web Portal Capture |
| Defense Evasion | Masquerading | T1036.005 | Match Legitimate Name |

## 🎓 Investigation Findings
1. **Attack Sophistication:** Low-Medium
   - No SSL on phishing site
   - Basic brand impersonation
   - SPF/DMARC failures easily detectable

2. **Social Engineering Effectiveness:** High
   - Urgency language ("account limited")
   - Brand authority (PayPal trust)
   - Clear call-to-action

3. **Detection Gaps:**
   - Email gateway missed due to domain reputation lag
   - Users not trained on header analysis
   - No URL rewriting in place

## 📈 Strategic Recommendations
1. **Technical Controls:**
   - Implement URL analysis in email gateway
   - Deploy DMARC with strict policies
   - Add typosquatting detection algorithms

2. **Process Improvements:**
   - Establish 15-minute IOC blocking SLA
   - Create phishing playbook for SOC analysts
   - Implement automated threat intelligence feeds

3. **Human Factors:**
   - Quarterly phishing simulation exercises
   - Just-in-time training when threats detected
   - Reward system for user reporting

## 🔗 Related Incidents
- Similar campaign targeting Microsoft 365 credentials (Case #2024-002)
- PayPal phishing wave observed across industry (Threat Intel Bulletin #45)

---
**Investigator:** Renaldi | SOC Analyst  
**Report Date:** 2026-01-30  
**Tools Used:** MXToolbox, VirusTotal, AbuseIPDB, AlienVault OTX  
**Time to Resolution:** 2 hours from detection to containment  

*This investigation demonstrates proactive threat hunting and rapid incident response capabilities.*

---

## 📁 Supporting Evidence
- [Email Headers](../analysis/email-headers.txt)
- [IOC List](../analysis/iocs.txt)
- [MXToolbox Results](../analysis/mxtoolbox-results.txt)
- [Screenshots](../screenshots/)

---
**Confidentiality:** This report contains sensitive security information. Distribution restricted to authorized personnel only.
