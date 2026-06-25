SPL & DHL Phishing Campaign - Detection Engineering & Forensic Triage

Status: All Channels Exhausted - Awaiting Takedown Decisions

Last Updated: June 25, 2026

---

Overview

This repository documents a live forensic triage of a sophisticated multi-layered phishing campaign targeting KSA citizens via email. What began as a simple 20 SAR customs fee lure revealed a four-layer criminal infrastructure with dynamic path randomization, single-use encrypted tokens per victim session, and domain rotation capabilities to evade takedowns.

The only stable detection anchors across all campaign URLs are two static parameters that persist even after domain rotation: the campaign fingerprint (ptf) and the C2 backend address (oho).

---

Investigation Timeline

Stage 1 - The Lure
Phishing email impersonates Saudi Post and KSA Customs demanding 20 SAR customs fee within 72 hours. Sender display domain: bahamas.gov.bs. DNS confirmed DMARC p=reject — direct spoofing prevented. Attacker used it as display name only.

Stage 2 - Compromised Entry Point (Layer 1)
Link leads to ccs-ti.com (Joomla 3.9.22, EOL August 2023). Kit found at non-standard typosquatted template path. Opening from real mobile browser revealed full Arabic SPL phishing page on ccs-ti.com: customs clearance required, 20 SAR fee, 72-hour deadline, weight mismatch warning. Template files verified clean via content inspection.

Stage 3 - TDS Bot Evasion Confirmed (Layer 3)
curl requests returned empty. iPhone User-Agent returned HTTP 200. Cache-Control: no-store, no-cache confirmed dynamic PHP execution as of June 24, 2026 01:41:55 GMT.

Stage 4 - DHL Kit on Separate Domain (Layer 2)
Clicking the payment button redirected to veyipa.astronex.icu serving a professional DHL delivery-hold page in English with fake tracking code AIPD-1512-KL10. Campaign pivots from Arabic SPL impersonation to English DHL impersonation mid-flow.

Stage 5 - Single-Use Tokens and Path Randomization Confirmed (Layer 4)
Revisiting the ccs-ti.com link returned Unauthorized Access. Kit remained on server but per-session encrypted token had expired. Each email click generates a fresh token and a completely randomized path via the C2 backend, making URL-level blocking ineffective.

Stage 6 - Campaign Fingerprint Identified
Parameter analysis across multiple URLs revealed two static IoCs present in every campaign redirect regardless of domain or path rotation:
ptf=26934eb377001f66e37289a5c93fe284 (campaign fingerprint)
oho=t4.citadelenv.su (C2 backend)

Stage 7 - Domain Rotation to quickinsighthub.st (June 25, 2026)
After Cloudflare restricted veyipa.astronex.icu, operator activated kemevu.quickinsighthub.st on the same OrangeWebsite infrastructure. Identical ptf and oho confirmed same operator. Multiple randomized paths observed across sessions:
/xa/niju/saloni/lobuhi/index.php
/gone/mocufu/fe/bu/index.php
/kuxalu/jofopu/veke/index.php

---

Infrastructure Map

Victim receives phishing email with single-use encrypted token link
    |
    Click triggers token generation at t4.citadelenv.su
    Issues unique rpclk token + randomized path per session
    |
    ccs-ti.com (compromised Joomla 3.9.22 EOL host)
    Serves Arabic SPL kit (customs fee, 72hr deadline)
    |
    TDS: User-Agent check + token validation
    |
    +-- Bot / expired token: Unauthorized Access
    |
    +-- Real mobile browser + valid token: HTTP 200
              |
              Victim clicks payment button
              |
              [Domain Rotation Pool - all on OrangeWebsite]
              veyipa.astronex.icu (restricted by Cloudflare)
              kemevu.quickinsighthub.st (active, restricted by Cloudflare CDN)
              [potential additional domains unknown]
                        |
                        t4.citadelenv.su (TDS/C2 backend, Cloudflare, .su TLD)
                        Controls routing, token issuance, path randomization

---

Indicators of Compromise (IoCs)

Static Campaign Fingerprints (present in ALL campaign URLs across all domains):
ptf=26934eb377001f66e37289a5c93fe284
oho=t4.citadelenv.su

Entry Point URL:
https://ccs-ti.com/templates/purity_iii/etc/form/lnternationalppost/app/index.php

Phishing Kit Domain 1 (CDN restricted): veyipa.astronex.icu
Registrar: Dynadot LLC
Created: April 7, 2026

Phishing Kit Domain 2 (CDN restricted): kemevu.quickinsighthub.st
Registrar: IncogNET (incognet.io)
Registry: .ST Registry

Hosting (both domains): OrangeWebsite, Iceland (THORDC-AS)
Phishing Kit IPs: 104.21.83.28 / 172.67.210.230 (Cloudflare)

TDS/C2 Backend: t4.citadelenv.su
TDS/C2 IPs: 172.67.135.235 / 104.21.7.88 (Cloudflare)

Fake Tracking Code: AIPD-1512-KL10
Sender Display Domain: bahamas.gov.bs (DMARC p=reject, display name abuse)

Compromised Host: ccs-ti.com
Joomla Version: 3.9.22 (EOL since August 2023)
Web Server: Apache
SSL: Let's Encrypt R12, issued May 4 2026, expires Aug 2 2026

TDS Behavior:
Single-use encrypted tokens per session (rpclk parameter)
Fully randomized paths per session on kit domains
Token validity window: approximately 24 minutes (currts delta)
Post-expiry response: Unauthorized Access

---

Takedown Status

Cloudflare:
veyipa.astronex.icu: Restricted (Report ID: fb87731872d82c63)
kemevu.quickinsighthub.st: Restricted (Report ID: 7f9c9f1c2a0a5ad9)
t4.citadelenv.su: No longer visible (Report ID: b2e29e733a2612a3)

Dynadot (Registrar of astronex.icu):
Status: Under investigation
Case ID: ddcn:M6vV8z9U8p6C6l:ddcn
Two formal complaints filed via webform with evidence

IncogNET (Registrar of quickinsighthub.st):
Status: Ticket open
Ticket ID: 0625Y12O8
Referred by ST Registry (Ticket #388498)

ST Registry (.st TLD):
Status: Answered - referred to IncogNET
Original Ticket ID: 388498

OrangeWebsite (Origin hosting - both domains):
Status: No action taken
Three escalation emails sent
Automated responses only
Note: Self-described free speech host, resistant to takedown requests

CERT-SA: Notified
CERT Iceland: Notified (for pressure on OrangeWebsite)
Shortdot (.icu registry): Notified
Google Safe Browsing: Three phishing URLs submitted

---

Detection Coverage

The /detections folder contains the following rules:

sigma_proxy_spl_phish.yml
Monitors outbound proxy/web traffic for the static campaign parameters ptf=26934eb377001f66e37289a5c93fe284 and oho=t4.citadelenv.su across all domains. Path and domain rotation does not evade this rule.

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

If you identify this campaign in your environment, report to:
CERT-SA: cert@cert.gov.sa
Cloudflare Abuse: cloudflare.com/abuse/form
Dynadot Abuse: dynadot.com/report-abuse
IncogNET Abuse: portal.incognet.io
Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish
APWG: apwg.org/report-phishing

---

Triage Timeline

Date Detected: June 23, 2026
SPL Kit Observed on ccs-ti.com: June 24, 2026 11:24
DHL Kit Observed on veyipa.astronex.icu: June 24, 2026
Token Expiry Confirmed: June 24, 2026 05:24
Path Randomization Confirmed: June 24, 2026 05:29
Domain Rotation to quickinsighthub.st Detected: June 25, 2026 04:59
All Takedown Channels Exhausted: June 25, 2026
Current Status: Awaiting Dynadot and IncogNET domain suspension decisions
