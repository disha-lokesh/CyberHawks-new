/*
    GARUDATVA — yara-rules/c2_infrastructure.yar
    Detects command-and-control infrastructure baked into an APK:
    tunnelling services, Telegram/Discord/Firebase bot channels,
    hardcoded IP:port, Tor onion endpoints, and disposable-domain TLDs.

    DETECTION signatures only.
*/

rule C2_Tunnel_Services
{
    meta:
        category    = "c2_infrastructure"
        severity    = "high"
        family      = "c2"
        description = "Hardcoded tunnelling/relay services commonly used for mobile C2"
        author      = "GARUDATVA"

    strings:
        $t1 = "ngrok.io"          nocase ascii wide
        $t2 = "ngrok-free.app"    nocase ascii wide
        $t3 = "trycloudflare.com" nocase ascii wide
        $t4 = "serveo.net"        nocase ascii wide
        $t5 = "localhost.run"     nocase ascii wide
        $t6 = "portmap.io"        nocase ascii wide
        $t7 = "pagekite.me"       nocase ascii wide
        $t8 = "loca.lt"           nocase ascii wide

    condition:
        any of them
}

rule C2_Messaging_Channel
{
    meta:
        category    = "c2_infrastructure"
        severity    = "high"
        family      = "c2"
        description = "Telegram/Discord/Firebase used as exfiltration or command channel"
        author      = "GARUDATVA"

    strings:
        $tg1 = "api.telegram.org/bot" nocase ascii wide
        $tg2 = "sendMessage"          ascii wide
        $tg3 = "getUpdates"           ascii wide
        $dc  = "discord.com/api/webhooks" nocase ascii wide
        $fb  = "firebaseio.com"       nocase ascii wide
        $pb  = "pastebin.com/raw"     nocase ascii wide

    condition:
        ($tg1 and any of ($tg2, $tg3)) or any of ($dc, $fb, $pb)
}

rule C2_Dynamic_DNS
{
    meta:
        category    = "c2_infrastructure"
        severity    = "medium"
        family      = "c2"
        description = "Free dynamic-DNS providers used to hide rotating C2 hosts"
        author      = "GARUDATVA"

    strings:
        $d1 = "duckdns.org"   nocase ascii wide
        $d2 = "no-ip.org"     nocase ascii wide
        $d3 = "no-ip.com"     nocase ascii wide
        $d4 = "ddns.net"      nocase ascii wide
        $d5 = "hopto.org"     nocase ascii wide
        $d6 = "zapto.org"     nocase ascii wide
        $d7 = "serveo.net"    nocase ascii wide

    condition:
        any of them
}

rule C2_Hardcoded_Endpoint
{
    meta:
        category    = "c2_infrastructure"
        severity    = "medium"
        family      = "c2"
        description = "Hardcoded IPv4:port endpoints (likely raw C2 socket) and onion addresses"
        author      = "GARUDATVA"

    strings:
        // IPv4 with explicit port — typical raw-socket C2 (excludes obvious local nets is left to scoring layer)
        $ipport = /\b(\d{1,3}\.){3}\d{1,3}:\d{2,5}\b/ ascii wide
        $onion  = /[a-z2-7]{16,56}\.onion/ nocase ascii wide
        $sock   = "java.net.Socket" ascii wide

    condition:
        ($ipport and $sock) or $onion
}

rule C2_Disposable_TLD
{
    meta:
        category    = "c2_infrastructure"
        severity    = "low"
        family      = "c2"
        description = "URLs on free/disposable TLDs frequently abused for throwaway C2"
        author      = "GARUDATVA"

    strings:
        $u = /https?:\/\/[a-z0-9.\-]+\.(tk|ml|ga|cf|gq)\b/ nocase ascii wide

    condition:
        #u >= 1
}
