rule Sentry_Encoded_Web_Shell
{
    meta:
        id = "yara-encoded-web-shell-v1"
        title = "Obfuscated Web Shell Function Markers"
        description = "Detects heavily obfuscated web-shell function invocations that build commands through encoding and compression routines."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "critical"
        tags = "persistence remote-access"
    strings:
        $get_var = "@$_GET["
        $post_var = "@$_POST["
        $chr = "chr(0x"
        $gunzip = "gzuncompress("
        $rot13 = "base64_decode(str_rot13"
        $createfunc = "create_function"
    condition:
        2 of them
}