rule Sentry_Keylogger_API
{
    meta:
        id = "yara-keylogger-api-v1"
        title = "Keylogging API Marker Set"
        description = "Detects source or artifact content that references the Windows input-capture API surface used by keyloggers and credential spies."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "collection credential-access"
    strings:
        $gaks = "GetAsyncKeyState"
        $keybd = "keybd_event"
        $hook = "SetWindowsHookEx"
        $wh_kb = "WH_KEYBOARD_LL"
        $hkll = "LowLevelKeyboardProc"
    condition:
        2 of them
}