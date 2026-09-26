rule Sentry_Office_Macro_Marker
{
    meta:
        id = "yara-office-macro-v1"
        title = "Office Macro Execution Markers"
        description = "Detects VBA and DDE document markers that trigger automatic macro or field evaluation on document open."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "high"
        tags = "initial-access execution"
    strings:
        $auto_open = "AutoOpen()"
        $auto_underscore = "Auto_Open"
        $ddeauto = "DDEAUTO"
        $doc_open = "Private Sub Document_Open"
        $auto_exec = "AutoExec"
    condition:
        2 of them
}