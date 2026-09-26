rule Sentry_XSS_Probe
{
    meta:
        id = "yara-xss-probe-v1"
        title = "XSS Payload Probe Markers"
        description = "Detects web request or script content carrying reflected cross-site scripting detector payloads."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "initial-access"
    strings:
        $script_alert = "<script>alert(1)</script>"
        $svg_onload = "<svg/onload="
        $img_onerror = "<img src=x onerror="
        $js_alert = "javascript:alert(1)"
        $iframe_srcdoc = "<iframe srcdoc="
    condition:
        2 of them
}