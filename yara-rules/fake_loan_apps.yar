/*
    GARUDATVA — yara-rules/fake_loan_apps.yar
    Detects predatory / fake instant-loan apps: "no CIBIL / Aadhaar
    loan" marketing strings combined with mass contact, SMS, and
    gallery harvesting used for harassment-based recovery.

    DETECTION signatures only.
*/

rule FakeLoan_Marketing_Strings
{
    meta:
        category    = "fake_loan"
        severity    = "medium"
        family      = "fake_loan"
        description = "Predatory instant-loan marketing copy (no-documents / no-CIBIL hooks)"
        author      = "GARUDATVA"

    strings:
        $m1 = "no CIBIL"            nocase ascii wide
        $m2 = "instant loan"       nocase ascii wide
        $m3 = "aadhaar loan"       nocase ascii wide
        $m4 = "loan in 5 minutes"  nocase ascii wide
        $m5 = "no documents"       nocase ascii wide
        $m6 = "quick cash"         nocase ascii wide
        $m7 = "instant approval"   nocase ascii wide
        $m8 = "pan card loan"      nocase ascii wide
        $m9 = "no credit check"    nocase ascii wide
        $m10 = "paperless loan"    nocase ascii wide

    condition:
        2 of them
}

rule FakeLoan_Contact_Harvesting
{
    meta:
        category    = "fake_loan"
        severity    = "high"
        family      = "fake_loan"
        description = "Bulk contact + call-log + SMS harvesting for recovery harassment"
        author      = "GARUDATVA"

    strings:
        $p1 = "android.permission.READ_CONTACTS"  ascii wide
        $p2 = "android.permission.READ_CALL_LOG"  ascii wide
        $p3 = "android.permission.READ_SMS"       ascii wide
        $u1 = "ContactsContract"                  ascii wide
        $u2 = "content://contacts"                ascii wide
        $up = "uploadContacts"                    nocase ascii wide
        $up2= "contact_list"                      nocase ascii wide
        $net= "multipart/form-data"               ascii wide

    condition:
        2 of ($p*) and ($u1 or $u2) and any of ($up, $up2, $net)
}

rule FakeLoan_Media_Exfiltration
{
    meta:
        category    = "fake_loan"
        severity    = "high"
        family      = "fake_loan"
        description = "Gallery / media access used for blackmail-based loan recovery"
        author      = "GARUDATVA"

    strings:
        $m1 = "android.permission.READ_EXTERNAL_STORAGE"      ascii wide
        $m2 = "android.permission.READ_MEDIA_IMAGES"          ascii wide
        $store = "MediaStore.Images"                          ascii wide
        $up    = "uploadImages"                               nocase ascii wide
        $gal   = "gallery"                                    nocase ascii wide
        $bl    = "morph"                                      nocase ascii wide

    condition:
        any of ($m1, $m2) and $store and 1 of ($up, $gal, $bl)
}
