rule Sentry_Ransomware_Like_Marker
{
    meta:
        id = "yara-ransomware-marker-v1"
        title = "Ransomware-Like File Marker"
        description = "Detects widely documented ransomware family ransom-note and wallpaper marker strings in artifact content."
        author = "SentinelAI Detection Team"
        date = "2024-06-15"
        severity = "critical"
        tags = "impact ransomware"
    strings:
        $encrypted_banner = "your files have been encrypted"
        $contact_decrypt = "contact us for decryption"
        $readme_note = "@Please_Read_Me@"
        $wallpaper_marker = "decrypting_your_files"
        $vuln_note = "what happened to my computer"
    condition:
        2 of them
}