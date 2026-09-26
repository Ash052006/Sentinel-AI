rule Sentry_Run_Key_Persistence
{
    meta:
        id = "yara-run-key-persistence-v1"
        title = "Registry Run-Key Persistence Markers"
        description = "Detects registry Run-key and Startup-folder persistence reference strings used to keep implants resident across reboots."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "persistence"
    strings:
        $run_hklm = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $run_hkcu = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $startup = "Programs\\Startup\\"
        $schtasks = "schtasks /create"
        $run_subkey = "CurrentVersion\\RunOnce"
    condition:
        2 of them
}