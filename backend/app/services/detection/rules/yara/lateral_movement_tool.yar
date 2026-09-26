rule Sentry_LateralMovement_Tool
{
    meta:
        id = "yara-lateral-movement-tool-v1"
        title = "Lateral Movement Command Markers"
        description = "Detects script content carrying PsExec-style, WMI-remote, or net-use commands used to move laterally across a domain."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "lateral-movement"
    strings:
        $psexec = "psexec -s"
        $wmic_node = "wmic /node:"
        $netuse = "net use /user:"
        $schtasks_remote = "schtasks /run /s "
        $admin_share = "admin$"
    condition:
        2 of them
}