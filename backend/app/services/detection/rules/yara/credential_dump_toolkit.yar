rule Sentry_Credential_Dump_Toolkit
{
    meta:
        id = "yara-credential-dump-toolkit-v1"
        title = "Credential Dump Toolkit Command Markers"
        description = "Detects command or script content carrying modname and technique arguments of widely distributed credential-dumping toolkits."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "credential-access"
    strings:
        $prv_debug = "privilege::debug"
        $lsass_dump = "lsass::dump"
        $golden = "kerberos::golden"
        $dcsync = "dcsync"
        $hash_dump = "sekurlsa::pth"
    condition:
        2 of them
}