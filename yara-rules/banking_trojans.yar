/*
    GARUDATVA — yara-rules/banking_trojans.yar
    Detects Indian banking-trojan behaviour: SMS/OTP interception,
    bank sender-ID targeting, overlay (phishing) injection, and
    broadcast-abort of incoming SMS.

    Scanned surface: DEX strings, AndroidManifest.xml, assets.
    DETECTION signatures only.
*/

rule Bank_SMS_OTP_Interception
{
    meta:
        category    = "banking_trojan"
        severity    = "high"
        family      = "banking_trojan"
        description = "Intercepts incoming SMS to capture/exfiltrate banking OTPs"
        author      = "GARUDATVA"

    strings:
        $recv   = "android.provider.Telephony.SMS_RECEIVED"  ascii wide
        $perm1  = "android.permission.RECEIVE_SMS"           ascii wide
        $perm2  = "android.permission.READ_SMS"              ascii wide
        $abort  = "abortBroadcast"                           ascii wide
        $pdu    = "pdus"                                     ascii wide
        $otp    = /OTP[\s:is]{0,6}\d{4,8}/                   nocase ascii wide
        $otp_kw = "one time password"                        nocase ascii wide
        $share  = "do not share"                             nocase ascii wide

    condition:
        $recv and any of ($perm1, $perm2) and
        (2 of ($abort, $pdu, $otp, $otp_kw, $share))
}

rule Bank_Sender_ID_Targeting
{
    meta:
        category    = "banking_trojan"
        severity    = "high"
        family      = "banking_trojan"
        description = "Hardcoded Indian bank SMS header/sender IDs (filter-and-steal targeting)"
        author      = "GARUDATVA"

    strings:
        $s1 = "SBIINB"  nocase ascii wide
        $s2 = "ICICIB"  nocase ascii wide
        $s3 = "HDFCBK"  nocase ascii wide
        $s4 = "AXISBK"  nocase ascii wide
        $s5 = "KOTAKB"  nocase ascii wide
        $s6 = "PNBSMS"  nocase ascii wide
        $s7 = "CANBNK"  nocase ascii wide
        $s8 = "BOIIND"  nocase ascii wide
        $s9 = "CBSSBI"  nocase ascii wide
        $s10 = "ATMSBI" nocase ascii wide
        // typical TRAI header format e.g. VM-SBIINB, AD-ICICIB
        $hdr = /[A-Z]{2}-[A-Z]{6}/ ascii wide

    condition:
        3 of ($s*) or (2 of ($s*) and #hdr >= 2)
}

rule Bank_Overlay_Phishing
{
    meta:
        category    = "banking_trojan"
        severity    = "critical"
        family      = "banking_trojan"
        description = "Draws fake overlay/login windows over banking apps to harvest credentials"
        author      = "GARUDATVA"

    strings:
        $ov1  = "TYPE_APPLICATION_OVERLAY"               ascii wide
        $ov2  = "android.permission.SYSTEM_ALERT_WINDOW" ascii wide
        $ov3  = "addView"                                ascii wide
        $wv   = "loadDataWithBaseURL"                    ascii wide
        $inj  = "javascript:"                            nocase ascii wide
        $top  = "getRunningTasks"                        ascii wide
        $usage= "UsageStatsManager"                      ascii wide
        $bank = "bank"                                   nocase ascii wide

    condition:
        ($ov1 or $ov2) and $ov3 and
        (any of ($wv, $inj, $top, $usage)) and $bank
}

rule Bank_Card_Data_Harvest
{
    meta:
        category    = "banking_trojan"
        severity    = "high"
        family      = "banking_trojan"
        description = "Form fields harvesting card/CVV/PIN/netbanking credentials"
        author      = "GARUDATVA"

    strings:
        $f1 = "card_number"   nocase ascii wide
        $f2 = "cvv"           nocase ascii wide
        $f3 = "expiry"        nocase ascii wide
        $f4 = "card_holder"   nocase ascii wide
        $f5 = "netbanking"    nocase ascii wide
        $f6 = "mpin"          nocase ascii wide
        $f7 = "atm_pin"       nocase ascii wide

    condition:
        3 of them
}
