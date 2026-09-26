rule Sentry_SQL_Injection_Probe
{
    meta:
        id = "yara-sql-injection-probe-v1"
        title = "SQL Injection Probe Markers"
        description = "Detects request or script content containing classic SQL injection probe payloads used for error-based and blind injection testing."
        author = "SentinelAI Detection Team"
        date = "2026-09-23"
        severity = "medium"
        tags = "initial-access"
    strings:
        $or_1 = "' or '1'='1"
        $union_select = "union select"
        $union_all = "union all select"
        $schema = "information_schema.tables"
        $sleep = "pg_sleep("
    condition:
        2 of them
}