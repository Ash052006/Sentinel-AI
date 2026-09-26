rule Sentry_LSASS_Dump_Access
{
    meta:
        id = "yara-lsass-dump-access-v1"
        title = "LSASS Dump Access Markers"
        description = "Detects markers associated with dumping the Local Security Authority Subsystem Service process memory to harvest credentials."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "credential-access"
    strings:
        $procdump = "procdump.exe -ma lsass"
        $minidump = "MiniDumpWriteDump"
        $comsvcs = "comsvcs.dll"
        $lsass_dmp = "lsass.dmp"
        $rundump = "rundll32 comsvcs"
    condition:
        2 of them
}