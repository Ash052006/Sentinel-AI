rule Sentry_Web_Config_Leak
{
    meta:
        id = "yara-web-config-leak-v1"
        title = "Web Configuration Or Source Exposure Markers"
        description = "Detects content that exposes web-server source, backups, or diagnostic endpoints which often reveal application internals and credentials."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "discovery"
    strings:
        $git_config = ".git/config"
        $conn_strings = "connectionStrings"
        $phpinfo = "phpinfo();"
        $server_status = "server-status"
        $env_backup = "config.php.bak"
    condition:
        2 of them
}