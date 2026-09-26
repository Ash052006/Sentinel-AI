rule Sentry_Credential_Stealing
{
    meta:
        id = "yara-credential-stealing-v1"
        title = "Credential-Stealing Pattern"
        description = "Detects markers associated with credential dumping tooling and LSASS memory access in artifact content."
        author = "SentinelAI Detection Team"
        date = "2024-06-15"
        severity = "critical"
        tags = "credential-access"
    strings:
        $sekurlsa    = "sekurlsa::logonpasswords"
        $mimikatz    = "mimikatz"
        $lsass_ref   = "lsass.exe"
        $sam_dump    = "sam dump"
        $signer_marker = "signer_subprocess_docs"
    condition:
        2 of them
}