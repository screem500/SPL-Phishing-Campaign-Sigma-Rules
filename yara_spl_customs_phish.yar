/*
   YARA — Saudi Post (SPL) "Customs Clearance" phishing campaign
   Targets: the phishing-kit landing page (HTML) and the server-side
   harvester/dropper (PHP) recovered from compromised Joomla hosts.
   Defensive CTI use. TLP:GREEN.
*/

import "hash"

rule SPL_Customs_Phish_Landing_HTML
{
    meta:
        author      = "CTI Triage - SPL Phishing"
        date        = "2026-06-23"
        description = "Fake SPL/Saudi Customs clearance landing page (20 SAR / 72h advance-fee, card harvest)"
        reference   = "https://attack.mitre.org/techniques/T1566/002/"
        tlp         = "green"
        mitre_attack= "T1566.002, T1656"

    strings:
        // Brand impersonation
        $b1 = "Saudi Post"          nocase
        $b2 = "SPL"                 nocase
        $b3 = "splonline"           nocase
        $b4 = "Customs Clearance"   nocase
        // Campaign-specific lure
        $l1 = "weight mismatch"     nocase
        $l2 = "20 SAR"             nocase
        $l3 = "72 hours"            nocase
        $l4 = "20.00"               nocase
        // Look-alike kit path / asset references
        $p1 = "purity_iii/etc/form" nocase
        $p2 = "lnternationalppost"  nocase
        // Card-harvest form fields
        $c1 = "cardnumber"          nocase
        $c2 = /name=["']?(card|cc|cvv|cvc|pan|expiry|exp_date)/ nocase
        $c3 = "<input"              nocase

    condition:
        // an HTML doc that mixes SPL branding + the lure + a card field
        (uint32(0) == 0x4f444321 or $c3) and        // "<!DO"CTYPE or has inputs
        2 of ($b*) and
        1 of ($l*) and
        ( any of ($p*) or any of ($c1, $c2) )
}

rule SPL_Customs_Phish_Kit_PHP
{
    meta:
        author      = "CTI Triage - SPL Phishing"
        date        = "2026-06-23"
        description = "Server-side harvester/exfil component of the SPL customs phishing kit (Joomla template dir drop)"
        reference   = "https://attack.mitre.org/techniques/T1584/004/"
        tlp         = "green"
        mitre_attack= "T1584.004, T1608.005"

    strings:
        $php = "<?php"
        // exfil mechanics
        $m1 = "mail("                 nocase
        $m2 = "fopen("                nocase
        $m3 = "file_put_contents("    nocase
        $m4 = "fwrite("               nocase
        // harvested-data sinks / field names common to this kit
        $d1 = "cardnumber"            nocase
        $d2 = "cvv"                   nocase
        $d3 = "$_POST"                nocase
        $d4 = /result\.txt|log\.txt|data\.txt|cc\.txt/ nocase
        // anti-analysis / bot-filter boilerplate frequently bundled
        $a1 = "antibots"              nocase
        $a2 = "blocker"               nocase
        $a3 = "crawler"               nocase
        // campaign tie-in
        $t1 = "Saudi Post"            nocase
        $t2 = "lnternationalppost"    nocase

    condition:
        $php and
        $d3 and
        2 of ($d1, $d2, $d4) and
        1 of ($m*) and
        ( any of ($t*) or any of ($a*) )
}
