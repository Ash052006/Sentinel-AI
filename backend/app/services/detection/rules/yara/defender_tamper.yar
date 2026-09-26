rule Sentry_Defender_Tamper
{
    meta:
        id = "yara-defender-tamper-v1"
        title = "Security Product Tampering Markers"
        description = "Detects content that references disabling or modifying Microsoft Defender real-time protection settings, a common pre-execution tampering step."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "defense-evasion"
    strings:
        $rtm = "DisableRealtimeMonitoring"
        $btm = "DisableBehaviorMonitoring"
        $defender = "WinDefend"
        $mp = "Set-MpPreference"
        $sigupdate = "SignatureUpdate"
    condition:
        2 of them
}