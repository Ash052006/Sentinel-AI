rule Sentry_AMSI_Bypass
{
    meta:
        id = "yara-amsi-bypass-v1"
        title = "AMSI Bypass Technique Markers"
        description = "Detects references to Antimalware Scan Interface bypass primitives in scanned content, an indicator of script-scanner evasion prior to execution."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "defense-evasion"
    strings:
        $amsi_buffer = "AmsiScanBuffer"
        $amsi_failed = "AMSIInitFailed"
        $amsi_patch = "amsi_patch"
        $etw_marker = "ETWProvider"
        $amsi_ref = "amsi.dll"
    condition:
        2 of them
}