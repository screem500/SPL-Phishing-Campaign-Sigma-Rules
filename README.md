# SPL Phishing Campaign - Detection Engineering & Forensic Triage

## Overview

This repository contains production-grade Sigma Detection Rules and YARA signatures developed during a live forensic triage of a localized phishing campaign impersonating Saudi Post (SPL) and KSA Customs.



## Threat Intelligence & Root-Cause Analysis

Campaign Type: Phishing targeting KSA citizens via email, using a low-friction advance-fee lure (20 SAR customs fee).

Compromised Host: Legitimate business domain (ccs-ti.com, registered since 2009) running an unpatched Joomla 3.9.22 installation (End-of-Life since August 2023).

Observed Tactic: Attacker leveraged the Joomla Template Manager to inject a persistence backdoor (error.php) and host the phishing kit under /templates/purity_iii/etc/form/lnternationalppost/.

Exfiltration Vector: Local data sinks (data.txt, log.txt, result.txt) returned HTTP 404, indicating the kit does not store data locally. Suspected exfiltration to a remote C2 or Telegram Bot (unconfirmed, requires dynamic analysis to verify).



## Indicators of Compromise (IoCs)

Phishing URL:
https://ccs-ti.com/templates/purity_iii/etc/form/lnternationalppost/app/index.php

Confirmed Backdoors:
https://ccs-ti.com/templates/purity_iii/error.php
https://ccs-ti.com/templates/purity_iii/index.php

Sender Domain: bahamas.gov.bs

Compromised Host: ccs-ti.com

Joomla Version: 3.9.22 (EOL since August 2023)

Web Server: Apache



## Detection Coverage

The /detections folder contains the following rules:

sigma_proxy_spl_phish.yml
Monitors and alerts on outbound proxy/web traffic targeting the specific typosquatted path under ccs-ti.com.

sigma_email_spl_customs_lure.yml
Targets the email gateway layer by tracking specific bait strings ("weight mismatch", "20 SAR", "72 hours") combined with DMARC alignment gaps.

sigma_webserver_joomla_kit.yml
Designed for webserver log auditing to detect unauthorized directory creation and file writes under Joomla template paths.

yara_spl_customs_phish.yar
YARA signature for file-level detection of the phishing kit. Matches against known strings, path patterns, and structural indicators found in the recovered kit.


## Usage

Convert Sigma rules to your SIEM using sigma-cli:

For Splunk (proxy and email rules):
sigma convert -t splunk -p splunk sigma_proxy_spl_phish.yml
sigma convert -t splunk -p splunk sigma_email_spl_customs_lure.yml

For Elastic (webserver rule):
sigma convert -t elastic -p ecs_web sigma_webserver_joomla_kit.yml

For QRadar:
sigma convert -t qradar sigma_proxy_spl_phish.yml

Run YARA scan against a suspicious directory:
yara yara_spl_customs_phish.yar /path/to/scan/

---

## Triage Timeline
Date Detected: June 23, 2026
Analysis Completed: June 24, 2026
Rules Status: Production-ready
Date Detected: June 23, 2026
Analysis Completed: June 24, 2026
Rules Status: Production-ready
