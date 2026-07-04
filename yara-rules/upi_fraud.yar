/*
    GARUDATVA — yara-rules/upi_fraud.yar
    Detects abuse of UPI payment rails (GPay / PhonePe / BHIM / Paytm).
    Looks for hardcoded VPAs, UPI deep-link intents, collect/mandate
    request construction, and bundled-package targeting inside an APK.

    Scanned surface: DEX strings, AndroidManifest.xml, assets, resources.
    These rules describe attacker patterns for DETECTION only.
*/

rule UPI_DeepLink_Intent
{
    meta:
        category    = "upi_fraud"
        severity    = "medium"
        family      = "upi_fraud"
        description = "Hardcoded UPI deep-link intents used to trigger silent payments/collect"
        author      = "GARUDATVA"
        reference   = "NPCI UPI Linking Specs; upi:// URI scheme"

    strings:
        $pay     = "upi://pay"      nocase ascii wide
        $collect = "upi://collect"  nocase ascii wide
        $mandate = "upi://mandate"  nocase ascii wide
        // UPI URI parameters frequently assembled in code
        $p_pa = "pa="  ascii wide      // payee address (VPA)
        $p_pn = "pn="  ascii wide      // payee name
        $p_am = "am="  ascii wide      // amount
        $p_tn = "tn="  ascii wide      // transaction note
        $p_cu = "cu=INR" nocase ascii wide

    condition:
        any of ($pay, $collect, $mandate) and 2 of ($p_*)
}

rule UPI_Hardcoded_VPA
{
    meta:
        category    = "upi_fraud"
        severity    = "high"
        family      = "upi_fraud"
        description = "Hardcoded Virtual Payment Address (mule/collection account)"
        author      = "GARUDATVA"

    strings:
        // VPA handle = identifier@psp  — common PSP suffixes
        $vpa = /[a-zA-Z0-9.\-_]{2,64}@(oksbi|okhdfcbank|okicici|okaxis|ybl|ibl|axl|paytm|apl|upi|airtel|fbl|sbi|hdfcbank|icici|axisbank|kotak|barodampay|cnrb)\b/ nocase ascii wide

    condition:
        #vpa >= 1
}

rule UPI_Target_Apps_Bundled
{
    meta:
        category    = "upi_fraud"
        severity    = "low"
        family      = "upi_fraud"
        description = "Direct references to UPI app packages (intent redirection / app-presence checks)"
        author      = "GARUDATVA"

    strings:
        $phonepe = "com.phonepe.app"                              ascii wide
        $paytm   = "net.one97.paytm"                              ascii wide
        $bhim    = "in.org.npci.upiapp"                           ascii wide
        $gpay    = "com.google.android.apps.nbu.paisa.user"       ascii wide
        $cred    = "com.dreamplug.androidapp"                     ascii wide
        $amazon  = "in.amazon.mShop.android.shopping"             ascii wide
        $bankcheck = "queryIntentActivities"                      ascii wide

    condition:
        3 of ($phonepe, $paytm, $bhim, $gpay, $cred, $amazon) and $bankcheck
}

rule UPI_Auto_Collect_Abuse
{
    meta:
        category    = "upi_fraud"
        severity    = "high"
        family      = "upi_fraud"
        description = "Programmatic UPI collect/mandate request generation (pull-money scam pattern)"
        author      = "GARUDATVA"

    strings:
        $c1 = "collectRequest"      nocase ascii wide
        $c2 = "createCollect"       nocase ascii wide
        $c3 = "autopay"             nocase ascii wide
        $c4 = "recurringMandate"    nocase ascii wide
        $c5 = "collect_money"       nocase ascii wide
        $c6 = "TransactionType.COLLECT" nocase ascii wide

    condition:
        2 of them
}
