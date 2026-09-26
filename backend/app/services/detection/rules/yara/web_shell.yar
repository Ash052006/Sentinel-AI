rule Sentry_Web_Shell
{
    meta:
        id = "yara-web-shell-v1"
        title = "Web Shell Pattern"
        description = "Detects common web shell function invocation patterns in deployed artifact content."
        author = "SentinelAI Detection Team"
        date = "2024-06-15"
        severity = "critical"
        tags = "persistence remote-access"
    strings:
        $eval_post  = "eval($_POST["
        $shell_exec = "shell_exec($_GET["
        $system_call = "system($_REQUEST["
        $base64_eval = "base64_decode"
        $cmd_passthru = "passthru("
    condition:
        2 of them
}