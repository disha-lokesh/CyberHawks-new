/*
    GARUDATVA — yara-rules/aadhaar_harvesting.yar
    Detects collection / exfiltration of Indian identity PII:
    Aadhaar (UIDAI) and PAN. Aadhaar is a 12-digit number that never
    starts with 0 or 1 (Verhoeff-checksummed); PAN is AAAAA9999A.

    DETECTION signatures only.
*/

rule Aadhaar_Number_Pattern
{
    meta:
        category    = "aadhaar_harvesting"
        severity    = "medium"
        family      = "pii_theft"
        description = "Aadhaar number regex present in code/assets (12-digit, leading 2-9)"
        author      = "GARUDATVA"
        reference   = "UIDAI Aadhaar number format"

    strings:
        // 12 digits, optional space/hyphen grouping, leading digit 2-9
        $aadhaar = /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/ ascii wide

    condition:
        #aadhaar >= 1
}

rule PAN_Number_Pattern
{
    meta:
        category    = "aadhaar_harvesting"
        severity    = "medium"
        family      = "pii_theft"
        description = "PAN (Permanent Account Number) regex present in code/assets"
        author      = "GARUDATVA"

    strings:
        // 5 letters, 4 digits, 1 letter
        $pan = /\b[A-Z]{5}\d{4}[A-Z]\b/ ascii wide

    condition:
        #pan >= 1
}

rule Aadhaar_Keyword_Targeting
{
    meta:
        category    = "aadhaar_harvesting"
        severity    = "high"
        family      = "pii_theft"
        description = "Identity-document keyword harvesting (Aadhaar/UIDAI/VID/PAN form capture)"
        author      = "GARUDATVA"

    strings:
        $a1 = "aadhaar"   nocase ascii wide
        $a2 = "aadhar"    nocase ascii wide
        $a3 = "uidai"     nocase ascii wide
        $a4 = "virtual id" nocase ascii wide
        $a5 = "\"vid\""   nocase ascii wide
        $a6 = "आधार"      wide ascii          // Devanagari "Aadhaar"
        $p1 = "pan card"  nocase ascii wide
        $p2 = "pan_number" nocase ascii wide
        $field = /(aadhaar|pan)[_ ]?(number|no|card)/ nocase ascii wide

    condition:
        2 of them
}

rule Aadhaar_DigiLocker_Abuse
{
    meta:
        category    = "aadhaar_harvesting"
        severity    = "high"
        family      = "pii_theft"
        description = "References to DigiLocker / m-Aadhaar packages for credential scraping"
        author      = "GARUDATVA"

    strings:
        $d1 = "in.gov.digilocker"          ascii wide
        $d2 = "in.gov.uidai.mAadhaarPlus"  ascii wide
        $d3 = "digilocker"                 nocase ascii wide
        $d4 = "ekyc"                       nocase ascii wide
        $d5 = "demographic"               nocase ascii wide

    condition:
        2 of them
}

rule PII_Exfiltration_Combo
{
    meta:
        category    = "aadhaar_harvesting"
        severity    = "critical"
        family      = "pii_theft"
        description = "Aadhaar/PAN keywords combined with network upload routines"
        author      = "GARUDATVA"

    strings:
        $id1 = "aadhaar"  nocase ascii wide
        $id2 = "pan"      nocase ascii wide
        $id3 = "kyc"      nocase ascii wide
        $n1  = "okhttp3"               ascii wide
        $n2  = "HttpURLConnection"     ascii wide
        $n3  = "multipart/form-data"   ascii wide
        $n4  = "application/json"      ascii wide

    condition:
        2 of ($id*) and 2 of ($n*)
}
