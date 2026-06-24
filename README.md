SPL & DHL Phishing Campaign - Detection Engineering & Forensic Triage

Overview

This repository documents a live forensic triage of a multi-layered phishing campaign targeting KSA citizens via email. What initially appeared as a simple phishing kit on a compromised Joomla site revealed a three-layer criminal infrastructure: a compromised business website as entry point, a dedicated phishing kit behind Cloudflare impersonating DHL, and a TDS/C2 backend for bot evasion and traffic control.

The repository contains production-grade Sigma Detection Rules and YARA signatures derived from this investigation.

---

Investigation Timeline

Stage 1 - The Lure
Phishing email arrives impersonating Saudi Post and KSA Customs demanding 20 SAR customs fee. Sender display address: noreply@bahamas.gov.bs. DNS analysis confirmed bahamas.gov.bs has DMARC p=reject, preventing direct spoofing. Attacker likely used it as display name only.

Stage 2 - Compromised Entry Point Discovered
Link in email leads to ccs-ti.com, a legitimate business domain registered since 2009. Joomla version fingerprinting via administrator/manifests/files/joomla.xml revealed version 3.9.22, a build from 2020 with no updates. Joomla 3.x branch reached End-of-Life in August 2023. Phishing kit found at a typosquatted non-standard template path. Template files (error.php, index.php) verified clean via content inspection — no malicious functions detected.

Stage 3 - TDS Bot Evasion Identified
curl requests to the kit returned empty responses. Switching to an iPhone User-Agent returned HTTP 200, confirming a Traffic Distribution System actively filtering bots and security scanners.

Stage 4 - Real Kit Exposed via Mobile Browser
Opening the link from a real mobile browser revealed the actual phishing kit on a separate domain: veyipa.astronex.icu. The kit impersonates DHL with a professional delivery-hold page and a fake tracking code (AIPD-1512-KL10), prompting victims to confirm delivery details and pay a fee.

Stage 5 - Full Infrastructure Mapped
DNS and header analysis revealed all infrastructure behind Cloudflare. The TDS/C2 backend domain t4.citadelenv.su was found embedded as an explicit parameter (oho=t4.citadelenv.su) in the redirect URL. Returns HTTP 500 on direct access, confirming it requires specific parameters to operate. Uses .su TLD (Soviet Union legacy domain) commonly associated with cybercriminal infrastructure.

---

Infrastructure Map

Victim receives phishing email
    |
    ccs-ti.com (compromised business site, Joomla 3.9.22 EOL)
    |
    TDS: User-Agent check
    |
    +-- Bot / scanner: empty response (blocked)
    |
    +-- Real mobile browser: HTTP 200
              |
              veyipa.astronex.icu (DHL phishing kit, behind Cloudflare)
                        |
                        t4.citadelenv.su (TDS/C2 backend, behind Cloudflare, .su TLD)

---

Indicators of Compromise (IoCs)

Entry Point URL:
https://ccs-ti.com/templates/purity_iii/etc/form/lnternationalppost/app/index.php

Phishing Kit Domain: veyipa.astronex.icu
Phishing Kit IPs: 104.21.83.28 / 172.67.210.230 (Cloudflare)

TDS/C2 Backend: t4.citadelenv.su
TDS/C2 IPs: 172.67.135.235 / 104.21.7.88 (Cloudflare)

Fake Tracking Code: AIPD-1512-KL10
Sender Display Domain: bahamas.gov.bs (DMARC p=reject, display name abuse suspected)

Compromised Host: ccs-ti.com
Joomla Version: 3.9.22 (EOL since August 2023)
Web Server: Apache
SSL Certificate: Let's Encrypt R12, issued May 4 2026, expires Aug 2 2026

Kit Activity Confirmed: Cache-Control: no-store, no-cache, must-revalidate
Timestamp: Wed, 24 Jun 2026 01:41:55 GMT

---

Detection Coverage

The /detections folder contains the following rules:

sigma_proxy_spl_phish.yml
Monitors outbound proxy/web traffic targeting the typosquatted path under ccs-ti.com and the phishing kit domain veyipa.astronex.icu.

sigma_email_spl_customs_lure.yml
Targets the email gateway layer tracking bait strings ("weight mismatch", "20 SAR", "72 hours", "DELIVERY PENDING") combined with DMARC alignment gaps.

sigma_webserver_joomla_kit.yml

Detects unauthorized directory creation and file writes under Joomla template paths in webserver logs.

yara_spl_customs_phish.yar
YARA signature matching known strings, path patterns, and structural indicators from the recovered kit.

---

Usage

Convert Sigma rules to your SIEM using sigma-cli:

For Splunk:
sigma convert -t splunk -p splunk sigma_proxy_spl_phish.yml
sigma convert -t splunk -p splunk sigma_email_spl_customs_lure.yml

For Elastic:
sigma convert -t elastic -p ecs_web sigma_webserver_joomla_kit.yml

For QRadar:
sigma convert -t qradar sigma_proxy_spl_phish.yml

Run YARA scan:
yara yara_spl_customs_phish.yar /path/to/scan/

---

Reporting

This campaign is active. If you identify it in your environment, report to:
- CERT-SA (National Cybersecurity Authority)
- Saudi Post abuse team
- Hosting provider of ccs-ti.com
- Cloudflare Abuse for veyipa.astronex.icu and t4.citadelenv.su
- Google Safe Browsing
- APWG (Anti-Phishing Working Group)

---

Triage Timeline

Date Detected: June 23, 2026
Analysis Completed: June 24, 2026
Rules Status: Production-ready
