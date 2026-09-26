rule Sentry_Credential_Exposure
{
    meta:
        id = "yara-credential-exposure-v1"
        title = "Exposed Credential Material in Log Content"
        description = "Detects log or config content that embeds credential material and sensitive key-bearing assignment strings, indicating accidental credential leakage."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "credential-access"
    strings:
        $password = "password="
        $client_cred = "client_secret="
        $privkey = "BEGIN PRIVATE KEY"
        $aws = "aws_secret_access_key="
        $apikey = "api_key="
    condition:
        2 of them
}