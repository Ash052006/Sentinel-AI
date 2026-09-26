rule Sentry_Script_Obfuscation
{
    meta:
        id = "yara-script-obfuscation-v1"
        title = "Heavy Script Obfuscation Markers"
        description = "Detects script content assembled through repeated character-code decoding and deferred execution, a hallmark of obfuscated droppers."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "defense-evasion execution"
    strings:
        $fromcharcode = "String.fromCharCode"
        $atob = "eval(atob("
        $decode_uri = "decodeURIComponent("
        $fpayload = "function(p,a,c,k,e,r)"
        $charat = "charCodeAt(0)"
    condition:
        2 of them
}