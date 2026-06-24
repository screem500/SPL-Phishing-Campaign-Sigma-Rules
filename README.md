SPL & DHL Phishing Campaign - Detection Engineering & Forensic Triage

Overview

This repository documents a live forensic triage of a sophisticated multi-layered phishing campaign targeting KSA citizens via email. What began as a simple 20 SAR customs fee lure revealed a four-layer criminal infrastructure with dynamic path randomization and single-use encrypted tokens per victim session, making traditional URL-based blocking ineffective. The only stable detection anchors across all campaign URLs are two static parameters: the campaign fingerprint (ptf) and the C2 backend address (oho).

The repository contains production-grade Sigma Detection Rules and YARA signatures derived from this investigation.

---

Investigation Timeline

Stage 1 - The Lure
Phishing email impersonates Saudi Post and KSA Customs demanding 20 SAR customs fee within 72 hours. Sender display domain: bahamas.gov.bs. DNS confirmed DMARC p=reject — direct spoofing prevented. Attacker used it as display name only.

Stage 2 - Compromised Entry Point (Layer 1)
Link leads to ccs-ti.com (Joomla 3.9.22, EOL August 2023). Kit found at non-standard typosquatted template path. Opening from real mobile browser at 11:24 revealed full Arabic SPL phishing page on ccs-ti.com: customs clearance required, 20 SAR fee, 72-hour deadline, weight mismatch warning. Template files verified clean via content inspection.

Stage 3 - TDS Bot Evasion Confirmed
curl requests returned empty. iPhone User-Agent returned HTTP 200. Cache-Control: no-store, no-cache confirmed dynamic PHP execution as of June 24, 2026 01:41:55 GMT.

Stage 4 - DHL Kit on Separate Domain (Layer 2)
Clicking the payment button redirected to veyipa.astronex.icu serving a professional DHL delivery-hold page in English with fake tracking code AIPD-1512-KL10. Campaign pivots from Arabic SPL impersonation to English DHL impersonation mid-flow to maximize victim trust.

Stage 5 - Token Expiry Confirms Single-Use Mechanism (Layer 3)
Revisiting the ccs-ti.com link at 5:24 returned "Unauthorized Access" on blank page. curl still returned HTTP 200 confirming kit remained on server. The rpclk parameter in the redirect URL is a single-use encrypted per-session token that invalidates after first use or time expiry.

Stage 6 - Path Randomization and Campaign Fingerprint Identified (Layer 4)
Opening the email again from Outlook at 5:29 (24 minutes later) generated a completely new redirect. The path on veyipa.astronex.icu changed entirely:

Previous path: /kiwusu/ga/goye/cisazode/ca/index.php
New path:      /rodige/yetifu/pili/index.php

Parameter analysis across both URLs revealed:

Changing per session (dynamic):
- rpclk: unique encrypted session token
- p: session hash
- currts: Unix timestamp (1782266744 → 1782268184, delta = 1440 seconds = 24 minutes)

Static across all campaign URLs (stable IoCs):
- oho=t4.citadelenv.su (C2 backend address)
- ptf=26934eb377001f66e37289a5c93fe284 (campaign fingerprint)

The ptf and oho parameters are the only reliable detection anchors in this campaign since all paths and tokens change per session.

---

Infrastructure Map

Victim receives phishing email
    |
    Click triggers token generation at t4.citadelenv.su
    Issues unique rpclk token + randomized path per session
    |
    ccs-ti.com (compromised Joomla 3.9.22 EOL host)
    Serves Arabic SPL kit (customs fee, 72hr deadline)
    |
    TDS: User-Agent check + token validation
    |
    +-- Bot / expired token: "Unauthorized Access"
    |
    +-- Real mobile + valid token: HTTP 200
              |
              Victim clicks payment button
              |
              veyipa.astronex.icu/[randomized path]/index.php
              DHL phishing kit (Cloudflare)
                        |
                        t4.citadelenv.su (TDS/C2 backend, Cloudflare, .su TLD)
                        Controls routing, token issuance, path randomization, data collection

---

Indicators of Compromise (IoCs)

Static Campaign Fingerprints (present in ALL campaign URLs):
ptf=26934eb377001f66e37289a5c93fe284
oho=t4.citadelenv.su

Entry Point URL:
https://ccs-ti.com/templates/purity_iii/etc/form/lnternationalppost/app/index.php

Phishing Kit Domain (Layer 1): ccs-ti.com
Phishing Kit Domain (Layer 2): veyipa.astronex.icu
Phishing Kit IPs: 104.21.83.28 / 172.67.210.230 (Cloudflare)

TDS/C2 Backend: t4.citadelenv.su
TDS/C2 IPs: 172.67.135.235 / 104.21.7.88 (Cloudflare)

Fake Tracking Code: AIPD-1512-KL10
Sender Display Domain: bahamas.gov.bs (DMARC p=reject, display name abuse)

Compromised Host: ccs-ti.com
Joomla Version: 3.9.22 (EOL since August 2023)
Web Server: Apache
SSL: Let's Encrypt R12, issued May 4 2026, expires Aug 2 2026

Kit Confirmed Active: Cache-Control: no-store, no-cache, must-revalidate
Timestamp: Wed, 24 Jun 2026 01:41:55 GMT

TDS Behavior:
- Single-use encrypted tokens per session (rpclk parameter)
- Randomized paths on veyipa.astronex.icu per session
- Post-expiry response: "Unauthorized Access"
- Token validity window: approximately 24 minutes (based on currts delta)

---

Detection Coverage

The /detections folder contains the following rules:

sigma_proxy_spl_phish.yml
Monitors outbound proxy/web traffic for the static campaign parameters ptf=26934eb377001f66e37289a5c93fe284 and oho=t4.citadelenv.su, and traffic to veyipa.astronex.icu and the entry-point path on ccs-ti.com.

sigma_email_spl_customs_lure.yml
Targets the email gateway layer tracking bait strings ("weight mismatch", "20 SAR", "72 hours", "DELIVERY PENDING") combined with DMARC alignment gaps from bahamas.gov.bs.

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

This campaign is active. Report to:
CERT-SA (National Cybersecurity Authority)
Saudi Post abuse team
Hosting provider of ccs-ti.com
Cloudflare Abuse for veyipa.astronex.icu and t4.citadelenv.su
Google Safe Browsing
APWG (Anti-Phishing Working Group)

---

Triage Timeline

Date Detected: June 23, 2026
SPL Kit Observed: June 24, 2026 11:24
DHL Kit Observed: June 24, 2026 (via mobile redirect)
Token Expiry Confirmed: June 24, 2026 05:24
Path Randomization Confirmed: June 24, 2026 05:29
Analysis Completed: June 24, 2026
Rules Status: Production-ready
