rule Sentry_SSH_Persistence_Key
{
    meta:
        id = "yara-ssh-persistence-v1"
        title = "SSH Key Persistence Markers"
        description = "Detects script or configuration content that installs SSH public keys for zero-hour access persistence on Unix-like hosts."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "persistence"
    strings:
        $auth_keys = "authorized_keys"
        $ssh_rsa = "ssh-rsa "
        $id_rsa = ".ssh/id_rsa"
        $known_hosts = ".ssh/known_hosts"
        $permit_root = "PermitRootLogin"
    condition:
        2 of them
}