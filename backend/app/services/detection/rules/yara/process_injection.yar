rule Sentry_Process_InjectionAPI
{
    meta:
        id = "yara-process-injection-v1"
        title = "Process Injection API Marker Set"
        description = "Detects source or artifact content that references Windows process-injection primitive APIs used for remote thread and APC injection."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "defense-evasion privilege-escalation"
    strings:
        $valloc = "VirtualAllocEx"
        $wpm = "WriteProcessMemory"
        $crt = "CreateRemoteThread"
        $ntcrt = "NtCreateThreadEx"
        $queueapc = "QueueUserAPC"
    condition:
        2 of them
}