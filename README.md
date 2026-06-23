# SPL Phishing Campaign - Detection Engineering & Forensic Triage

## 📌 Overview
This repository contains production-grade **Sigma Detection Rules** developed during a live forensic triage of a localized phishing campaign impersonating **Saudi Post (SPL)** and **KSA Customs**. 

## 🛡️ Threat Intelligence & Root-Cause Analysis
- **Campaign Type:** Advance-fee smishing/phishing targeting KSA citizens (demanding 20 SAR).
- **Compromised Host:** Legitimate business domain running an unpatched **Joomla 3.9.22** installation (End-of-Life since August 2023).
- **Observed Tactic:** Attacker leveraged the Joomla Template Manager to inject a persistence backdoor (`error.php`) and host the phishing kit under `/templates/purity_iii/etc/form/lnternationalppost/`.
- **Exfiltration Vector:** Kit utilizes external API exfiltration (HTTP 404 on local sinks), likely dumping card data to a remote C2 or Telegram Bot.

## 🚀 Detection Coverage (Sigma Rules)
The `/detections` folder contains the following YAML rules:
1. **`sigma_proxy_spl_phish.yml`**: Monitors and alerts on outbound proxy/web traffic targeting the specific typosquatted path.
2. **`sigma_email_spl_customs_lure.yml`**: Targets the email gateway layer by tracking specific bait strings ("weight mismatch", "20 SAR", "72 hours") combined with DMARC alignment gaps.
3. **`sigma_webserver_joomla_kit.yml`**: Designed for webserver log auditing to detect unauthorized directory creation under template paths.

## 🛠️ Usage
Convert these rules to your specific SIEM language (Splunk, Elastic, QRadar) using `sigma-cli`:
```bash
sigma convert -t splunk -p splunk_windows sigma_proxy_spl_phish.yml
