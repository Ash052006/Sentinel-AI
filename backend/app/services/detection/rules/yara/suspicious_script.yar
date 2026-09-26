rule Sentry_Suspicious_Script
{
    meta:
        id = "yara-suspicious-script-v1"
        title = "Suspicious Script Pattern"
        description = "Detects obfuscated or encoded script patterns common in payload staging and in-memory execution."
        author = "SentinelAI Detection Team"
        date = "2024-06-15"
        severity = "high"
        tags = "execution obfuscation"
    strings:
        $obfuscated_var = "var _0x"
        $eval_function  = "eval(function"
        $hidden_window  = "-windowstyle hidden"
        $encoded_cmd    = "powershell -enc"
        $frombase64     = "FromBase64String"
    condition:
        2 of them
}