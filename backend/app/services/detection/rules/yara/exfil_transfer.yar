rule Sentry_Exfil_Transfer
{
    meta:
        id = "yara-exfil-transfer-v1"
        title = "Data Exfiltration Transfer Markers"
        description = "Detects batch or shell content that stages bulk file transfer over FTP, HTTP, or raw sockets outside approved channels."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "exfiltration"
    strings:
        $ftp_script = "ftp -s:"
        $mput = "mput *"
        $curl_upload = "curl -F"
        $nc_listen = "nc -lvp"
        $py_http = "python -m http.server"
    condition:
        2 of them
}