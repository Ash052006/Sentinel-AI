rule Sentry_Reverse_Shell_Token
{
    meta:
        id = "yara-reverse-shell-token-v1"
        title = "Reverse Shell Token Markers"
        description = "Detects canonical reverse-shell invocation patterns passed to bash, netcat, and ncat inside script or config content."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "execution persistence"
    strings:
        $bash_tcp = "bash -i >& /dev/tcp/"
        $nc_shell = "nc -e /bin/sh"
        $ncat_shell = "ncat -e /bin/bash"
        $tcp_dev = "-i /dev/tcp/"
        $spawn_sh = "-c sh -i"
    condition:
        2 of them
}