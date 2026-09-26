rule Sentry_Phishing_Lure
{
    meta:
        id = "yara-phishing-lure-v1"
        title = "Credential Phishing Lure Markers"
        description = "Detects email or web content carrying urgent account-password lure phrasing used to harvest credentials."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "initial-access"
    strings:
        $reset = "Urgent Password Reset"
        $locked = "account has been locked"
        $expires = "Your password expires"
        $verify = "Verify your account"
        $login_now = "Click here to login"
    condition:
        2 of them
}