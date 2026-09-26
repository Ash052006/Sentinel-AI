rule Sentry_PowerShell_Artifact
{
    meta:
        id = "yara-powershell-artifact-v1"
        title = "Suspicious PowerShell Artifact"
        description = "Detects script content combining encoded command execution and remote content retrieval common in malware staging."
        author = "SentinelAI Detection Team"
        date = "2024-06-15"
        severity = "high"
        tags = "execution command-and-control"
    strings:
        $encoded = "-EncodedCommand"
        $noprofile = "-NoProfile"
        $download = "DownloadString"
        $iex_ref = "Invoke-Expression"
        $named_pipe = "NamedPipe"
    condition:
        2 of them
}