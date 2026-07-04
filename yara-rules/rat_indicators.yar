/*
    GARUDATVA — yara-rules/rat_indicators.yar
    Detects Android Remote Access Trojan capability: accessibility
    abuse, screen capture, remote command dispatch, keylogging, and
    fingerprints of known mobile RAT families.

    DETECTION signatures only.
*/

rule RAT_Accessibility_Abuse
{
    meta:
        category    = "rat"
        severity    = "critical"
        family      = "rat"
        description = "Accessibility-service abuse for remote UI control / auto-grant"
        author      = "GARUDATVA"

    strings:
        $a1 = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii wide
        $a2 = "onAccessibilityEvent"                          ascii wide
        $a3 = "performGlobalAction"                           ascii wide
        $a4 = "GLOBAL_ACTION_BACK"                            ascii wide
        $a5 = "AccessibilityNodeInfo"                         ascii wide
        $a6 = "performAction"                                 ascii wide
        $auto = "ACTION_CLICK"                                ascii wide

    condition:
        $a1 and 3 of ($a2, $a3, $a4, $a5, $a6, $auto)
}

rule RAT_Screen_Capture
{
    meta:
        category    = "rat"
        severity    = "high"
        family      = "rat"
        description = "Live screen capture / streaming via MediaProjection"
        author      = "GARUDATVA"

    strings:
        $s1 = "MediaProjection"             ascii wide
        $s2 = "createScreenCaptureIntent"   ascii wide
        $s3 = "VirtualDisplay"              ascii wide
        $s4 = "ImageReader"                 ascii wide
        $s5 = "createScreenshot"            nocase ascii wide

    condition:
        3 of them
}

rule RAT_Remote_Command_Dispatch
{
    meta:
        category    = "rat"
        severity    = "high"
        family      = "rat"
        description = "Command-and-control dispatcher handling remote operator commands"
        author      = "GARUDATVA"

    strings:
        $c1 = "screenshot"   nocase ascii wide
        $c2 = "keylog"       nocase ascii wide
        $c3 = "getContacts"  nocase ascii wide
        $c4 = "getSms"       nocase ascii wide
        $c5 = "recordAudio"  nocase ascii wide
        $c6 = "getLocation"  nocase ascii wide
        $c7 = "executeCommand" nocase ascii wide
        $c8 = "callForward"  nocase ascii wide
        $disp = /"?(cmd|command|action|task)"?\s*[:=]/ nocase ascii wide

    condition:
        4 of ($c*) and $disp
}

rule RAT_Keylogger
{
    meta:
        category    = "rat"
        severity    = "high"
        family      = "rat"
        description = "Keystroke logging via accessibility text-change events"
        author      = "GARUDATVA"

    strings:
        $k1 = "TYPE_VIEW_TEXT_CHANGED"   ascii wide
        $k2 = "getText"                  ascii wide
        $k3 = "keystroke"                nocase ascii wide
        $k4 = "keylogger"                nocase ascii wide
        $k5 = "EditText"                 ascii wide

    condition:
        ($k1 and $k2) or 2 of ($k3, $k4, $k5)
}

rule RAT_Known_Family_Fingerprints
{
    meta:
        category    = "rat"
        severity    = "critical"
        family      = "rat"
        description = "Class/string fingerprints of known Android RAT/banker families"
        author      = "GARUDATVA"
        reference   = "Public IOC reporting: SpyNote, AndroRAT, Cerberus, Hydra, Hook, Octo"

    strings:
        $f1 = "androrat"          nocase ascii wide
        $f2 = "spynote"           nocase ascii wide
        $f3 = "ahmyth"            nocase ascii wide
        $f4 = "cerberus"          nocase ascii wide
        $f5 = "com.hydra"         nocase ascii wide
        $f6 = "OctoBot"           nocase ascii wide
        $f7 = "DroidJack"         nocase ascii wide
        $f8 = "ApkPenguin"        nocase ascii wide

    condition:
        any of them
}
