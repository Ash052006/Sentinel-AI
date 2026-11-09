"""Authoritative MITRE ATT&CK Mapping Subsystem.

Provides bidirectional and heuristic mapping between detection rules
(Sigma / YARA), rule identifiers, tags, and official MITRE ATT&CK techniques,
tactics, and descriptions, along with recommended SOAR containment responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class MitreTechnique:
    """An official MITRE ATT&CK technique reference with mapped response guidance."""

    technique_id: str
    name: str
    tactic: str
    url: str
    recommended_responses: tuple[str, ...] = ()
    playbook_ids: tuple[str, ...] = ()

    def to_claim_text(self) -> str:
        base = f"Technique {self.technique_id} ({self.name}) — Tactic: {self.tactic}"
        if self.recommended_responses:
            base += f" [Recommended SOAR Response: {', '.join(self.recommended_responses)}]"
        return base


def _tech(
    technique_id: str,
    name: str,
    tactic: str,
    recommended_responses: tuple[str, ...] = (),
    playbook_ids: tuple[str, ...] = (),
) -> MitreTechnique:
    url_id = technique_id.replace(".", "/")
    return MitreTechnique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"https://attack.mitre.org/techniques/{url_id}/",
        recommended_responses=recommended_responses,
        playbook_ids=playbook_ids,
    )


# ---------------------------------------------------------------------------
# Authoritative Rule-to-MITRE Catalog
# ---------------------------------------------------------------------------

RULE_MITRE_CATALOG: dict[str, list[MitreTechnique]] = {
    # -- Sigma Detection Rules ----------------------------------------------
    "11111111-1111-4111-8111-111111111111": [
        _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
        _tech("T1027", "Obfuscated Files or Information", "Defense Evasion",
              ("QUARANTINE_FILE",), ("quarantine_file",)),
    ],
    "22222222-2222-4222-8222-222222222222": [
        _tech("T1110.001", "Brute Force: Password Guessing", "Credential Access",
              ("DISABLE_ACCOUNT", "BLOCK_IP"), ("credential_theft_mitigation", "disable_account", "block_ip")),
    ],
    "33333333-3333-4333-8333-333333333333": [
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
        _tech("T1204.002", "User Execution: Malicious File", "Execution",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
    ],
    "44444444-4444-4444-8444-444444444444": [
        _tech("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
        _tech("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
              ("TERMINATE_SESSION", "DISABLE_ACCOUNT"), ("terminate_session", "disable_account")),
    ],
    "55555555-5555-4555-8555-555555555555": [
        _tech("T1021", "Remote Services", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
        _tech("T1133", "External Remote Services", "Initial Access",
              ("BLOCK_IP", "DISABLE_ACCOUNT"), ("c2_infrastructure_takedown", "block_ip")),
    ],
    "66666666-6666-4666-8666-666666666666": [
        _tech("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "77777777-7777-4777-8777-777777777777": [
        _tech("T1078", "Valid Accounts", "Initial Access",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"), ("credential_theft_mitigation", "disable_account")),
    ],
    "88888888-8888-4888-8888-888888888888": [
        _tech("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
              ("BLOCK_IP", "BLOCK_DOMAIN"), ("c2_infrastructure_takedown", "block_ip", "block_domain")),
        _tech("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "99999999-9999-4999-8999-999999999999": [
        _tech("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
        _tech("T1078.002", "Valid Accounts: Domain Accounts", "Privilege Escalation",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"), ("credential_theft_mitigation", "disable_account")),
    ],
    "10000000-0000-4000-8000-000000000000": [
        _tech("T1110.003", "Brute Force: Password Spraying", "Credential Access",
              ("DISABLE_ACCOUNT", "BLOCK_IP"), ("credential_theft_mitigation", "disable_account", "block_ip")),
    ],
    "11000000-0000-4000-8000-000000000000": [
        _tech("T1078.002", "Valid Accounts: Domain Accounts", "Defense Evasion",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"), ("credential_theft_mitigation", "disable_account")),
    ],
    "12000000-0000-4000-8000-000000000000": [
        _tech("T1078.001", "Valid Accounts: Default Accounts", "Initial Access",
              ("DISABLE_ACCOUNT",), ("disable_account",)),
    ],
    "13000000-0000-4000-8000-000000000000": [
        _tech("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "14000000-0000-4000-8000-000000000000": [
        _tech("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
        _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "15000000-0000-4000-8000-000000000000": [
        _tech("T1074.001", "Data Staged: Local Data Staging", "Collection",
              ("ISOLATE_ENDPOINT", "QUARANTINE_FILE"), ("endpoint_containment", "quarantine_file")),
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION",), ("terminate_session",)),
    ],
    "16000000-0000-4000-8000-000000000000": [
        _tech("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "17000000-0000-4000-8000-000000000000": [
        _tech("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "18000000-0000-4000-8000-000000000000": [
        _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "19000000-0000-4000-8000-000000000000": [
        _tech("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION", "ISOLATE_ENDPOINT"),
              ("credential_theft_mitigation", "disable_account", "isolate_endpoint")),
    ],
    "20000000-0000-4000-8000-000000000000": [
        _tech("T1090", "Proxy", "Command and Control",
              ("BLOCK_IP", "BLOCK_DOMAIN"), ("c2_infrastructure_takedown", "block_ip")),
    ],
    "21000000-0000-4000-8000-000000000000": [
        _tech("T1082", "System Information Discovery", "Discovery",
              ("TERMINATE_SESSION",), ("terminate_session",)),
        _tech("T1016", "System Network Configuration Discovery", "Discovery",
              ("TERMINATE_SESSION",), ("terminate_session",)),
        _tech("T1033", "System Owner/User Discovery", "Discovery",
              ("TERMINATE_SESSION",), ("terminate_session",)),
    ],
    "22000000-0000-4000-8000-000000000000": [
        _tech("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
              ("QUARANTINE_FILE", "BLOCK_DOMAIN"), ("quarantine_file", "block_domain")),
        _tech("T1204.002", "User Execution: Malicious File", "Execution",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
    ],
    "23000000-0000-4000-8000-000000000000": [
        _tech("T1505.003", "Server Software Component: Web Shell", "Persistence",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT", "TERMINATE_SESSION"),
              ("quarantine_file", "isolate_endpoint", "terminate_session")),
        _tech("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution",
              ("TERMINATE_SESSION",), ("terminate_session",)),
    ],
    "24000000-0000-4000-8000-000000000000": [
        _tech("T1021", "Remote Services", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "25000000-0000-4000-8000-000000000000": [
        _tech("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
              ("BLOCK_IP", "BLOCK_DOMAIN"), ("c2_infrastructure_takedown", "block_ip", "block_domain")),
    ],
    "26000000-0000-4000-8000-000000000000": [
        _tech("T1071.004", "Application Layer Protocol: DNS", "Command and Control",
              ("BLOCK_DOMAIN", "BLOCK_IP"), ("c2_infrastructure_takedown", "block_domain")),
    ],
    "27000000-0000-4000-8000-000000000000": [
        _tech("T1571", "Non-Standard Port", "Command and Control",
              ("BLOCK_IP",), ("block_ip",)),
    ],
    "28000000-0000-4000-8000-000000000000": [
        _tech("T1046", "Network Service Discovery", "Discovery",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],

    # -- YARA Detection Rules -----------------------------------------------
    "yara-amsi-bypass-v1": [
        _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "Sentry_AMSI_Bypass": [
        _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "yara-lsass-dump-access-v1": [
        _tech("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
              ("DISABLE_ACCOUNT", "ISOLATE_ENDPOINT", "TERMINATE_SESSION"),
              ("credential_theft_mitigation", "disable_account", "isolate_endpoint")),
    ],
    "Sentry_LSASS_Dump_Access": [
        _tech("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
              ("DISABLE_ACCOUNT", "ISOLATE_ENDPOINT", "TERMINATE_SESSION"),
              ("credential_theft_mitigation", "disable_account", "isolate_endpoint")),
    ],
    "yara-credential-dump-toolkit-v1": [
        _tech("T1003", "OS Credential Dumping", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "Sentry_Credential_Dump_Toolkit": [
        _tech("T1003", "OS Credential Dumping", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "yara-web-shell-v1": [
        _tech("T1505.003", "Server Software Component: Web Shell", "Persistence",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
    ],
    "Sentry_Web_Shell": [
        _tech("T1505.003", "Server Software Component: Web Shell", "Persistence",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
    ],
    "yara-encoded-web-shell-v1": [
        _tech("T1505.003", "Server Software Component: Web Shell", "Persistence",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
        _tech("T1027", "Obfuscated Files or Information", "Defense Evasion",
              ("QUARANTINE_FILE",), ("quarantine_file",)),
    ],
    "Sentry_Encoded_Web_Shell": [
        _tech("T1505.003", "Server Software Component: Web Shell", "Persistence",
              ("QUARANTINE_FILE", "ISOLATE_ENDPOINT"), ("quarantine_file", "isolate_endpoint")),
    ],
    "yara-web-config-leak-v1": [
        _tech("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "Sentry_Web_Config_Leak": [
        _tech("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "yara-run-key-persistence-v1": [
        _tech("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence",
              ("QUARANTINE_FILE", "TERMINATE_SESSION"), ("quarantine_file", "terminate_session")),
    ],
    "Sentry_Run_Key_Persistence": [
        _tech("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence",
              ("QUARANTINE_FILE", "TERMINATE_SESSION"), ("quarantine_file", "terminate_session")),
    ],
    "yara-ssh-persistence-v1": [
        _tech("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"), ("credential_theft_mitigation", "disable_account")),
    ],
    "Sentry_SSH_Persistence_Key": [
        _tech("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"), ("credential_theft_mitigation", "disable_account")),
    ],
    "yara-reverse-shell-token-v1": [
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "Sentry_Reverse_Shell_Token": [
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "yara-powershell-artifact-v1": [
        _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "Sentry_PowerShell_Artifact": [
        _tech("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "yara-suspicious-script-v1": [
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "Sentry_Suspicious_Script": [
        _tech("T1059", "Command and Scripting Interpreter", "Execution",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "yara-script-obfuscation-v1": [
        _tech("T1027", "Obfuscated Files or Information", "Defense Evasion",
              ("QUARANTINE_FILE",), ("quarantine_file",)),
    ],
    "Sentry_Script_Obfuscation": [
        _tech("T1027", "Obfuscated Files or Information", "Defense Evasion",
              ("QUARANTINE_FILE",), ("quarantine_file",)),
    ],
    "yara-defender-tamper-v1": [
        _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "Sentry_Defender_Tamper": [
        _tech("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "yara-process-injection-v1": [
        _tech("T1055", "Process Injection", "Privilege Escalation",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "Sentry_Process_InjectionAPI": [
        _tech("T1055", "Process Injection", "Privilege Escalation",
              ("TERMINATE_SESSION", "ISOLATE_ENDPOINT"), ("terminate_session", "isolate_endpoint")),
    ],
    "yara-keylogger-api-v1": [
        _tech("T1056.001", "Input Capture: Keylogging", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "Sentry_Keylogger_API": [
        _tech("T1056.001", "Input Capture: Keylogging", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"), ("credential_theft_mitigation", "quarantine_file")),
    ],
    "yara-lateral-movement-tool-v1": [
        _tech("T1021", "Remote Services", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "BLOCK_IP"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "Sentry_LateralMovement_Tool": [
        _tech("T1021", "Remote Services", "Lateral Movement",
              ("ISOLATE_ENDPOINT", "BLOCK_IP"), ("endpoint_containment", "isolate_endpoint")),
    ],
    "yara-phishing-lure-v1": [
        _tech("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
              ("QUARANTINE_FILE", "BLOCK_DOMAIN"), ("quarantine_file", "block_domain")),
    ],
    "Sentry_Phishing_Lure": [
        _tech("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
              ("QUARANTINE_FILE", "BLOCK_DOMAIN"), ("quarantine_file", "block_domain")),
    ],
    "yara-crypto-miner-v1": [
        _tech("T1496", "Resource Hijacking", "Impact",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "Sentry_Crypto_Miner_Marker": [
        _tech("T1496", "Resource Hijacking", "Impact",
              ("TERMINATE_SESSION", "QUARANTINE_FILE"), ("terminate_session", "quarantine_file")),
    ],
    "yara-ransomware-marker-v1": [
        _tech("T1486", "Data Encrypted for Impact", "Impact",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION", "BLOCK_IP"),
              ("ransomware_rapid_response", "endpoint_containment", "isolate_endpoint")),
    ],
    "Sentry_Ransomware_Like_Marker": [
        _tech("T1486", "Data Encrypted for Impact", "Impact",
              ("ISOLATE_ENDPOINT", "TERMINATE_SESSION", "BLOCK_IP"),
              ("ransomware_rapid_response", "endpoint_containment", "isolate_endpoint")),
    ],
    "yara-sql-injection-probe-v1": [
        _tech("T1190", "Exploit Public-Facing Application", "Initial Access",
              ("BLOCK_IP",), ("block_ip",)),
    ],
    "Sentry_SQL_Injection_Probe": [
        _tech("T1190", "Exploit Public-Facing Application", "Initial Access",
              ("BLOCK_IP",), ("block_ip",)),
    ],
    "yara-xss-probe-v1": [
        _tech("T1190", "Exploit Public-Facing Application", "Initial Access",
              ("BLOCK_IP",), ("block_ip",)),
    ],
    "Sentry_XSS_Probe": [
        _tech("T1190", "Exploit Public-Facing Application", "Initial Access",
              ("BLOCK_IP",), ("block_ip",)),
    ],
    "yara-exfil-transfer-v1": [
        _tech("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              ("BLOCK_IP", "BLOCK_DOMAIN", "ISOLATE_ENDPOINT"),
              ("c2_infrastructure_takedown", "block_ip")),
    ],
    "Sentry_Exfil_Transfer": [
        _tech("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              ("BLOCK_IP", "BLOCK_DOMAIN", "ISOLATE_ENDPOINT"),
              ("c2_infrastructure_takedown", "block_ip")),
    ],
    "yara-credential-stealing-v1": [
        _tech("T1555", "Credentials from Password Stores", "Credential Access",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"),
              ("credential_theft_mitigation", "disable_account")),
    ],
    "Sentry_Credential_Stealing": [
        _tech("T1555", "Credentials from Password Stores", "Credential Access",
              ("DISABLE_ACCOUNT", "TERMINATE_SESSION"),
              ("credential_theft_mitigation", "disable_account")),
    ],
    "yara-credential-exposure-v1": [
        _tech("T1552", "Unsecured Credentials", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"),
              ("credential_theft_mitigation", "disable_account")),
    ],
    "Sentry_Credential_Exposure": [
        _tech("T1552", "Unsecured Credentials", "Credential Access",
              ("DISABLE_ACCOUNT", "QUARANTINE_FILE"),
              ("credential_theft_mitigation", "disable_account")),
    ],
}


_TACTIC_BY_NAME: dict[str, str] = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def get_mitre_techniques_by_tag(tag: str) -> list[MitreTechnique]:
    """Parse technique patterns like attack.t1059.001 or standalone t1059."""
    cleaned = tag.strip().lower()
    m = re.search(r"t\d{4}(?:\.\d{3})?", cleaned)
    if m:
        tech_id = m.group(0).upper()
        # Derive generic guidance based on prefix or known technique
        responses = _infer_default_responses(tech_id)
        playbooks = _infer_default_playbooks(tech_id)
        return [_tech(tech_id, f"MITRE Technique {tech_id}", "Enterprise ATT&CK", responses, playbooks)]
    return []


def _infer_default_responses(tech_id: str) -> tuple[str, ...]:
    if tech_id.startswith("T1059"):
        return ("TERMINATE_SESSION", "QUARANTINE_FILE")
    if tech_id.startswith("T1071") or tech_id.startswith("T1090"):
        return ("BLOCK_IP", "BLOCK_DOMAIN")
    if tech_id.startswith("T1110") or tech_id.startswith("T1078") or tech_id.startswith("T1003"):
        return ("DISABLE_ACCOUNT", "TERMINATE_SESSION")
    if tech_id.startswith("T1021") or tech_id.startswith("T1486"):
        return ("ISOLATE_ENDPOINT", "TERMINATE_SESSION")
    return ("TERMINATE_SESSION",)


def _infer_default_playbooks(tech_id: str) -> tuple[str, ...]:
    if tech_id.startswith("T1059"):
        return ("terminate_session", "quarantine_file")
    if tech_id.startswith("T1071") or tech_id.startswith("T1090"):
        return ("c2_infrastructure_takedown", "block_ip")
    if tech_id.startswith("T1110") or tech_id.startswith("T1078") or tech_id.startswith("T1003"):
        return ("credential_theft_mitigation", "disable_account")
    if tech_id.startswith("T1021") or tech_id.startswith("T1486"):
        return ("ransomware_rapid_response", "endpoint_containment")
    return ("terminate_session",)


def get_mitre_techniques_for_rule(
    rule_id: str | None,
    tags: Sequence[str] = (),
    rule_title: str | None = None,
) -> list[MitreTechnique]:
    """Resolve authoritative MITRE ATT&CK techniques for a rule or finding."""
    if not rule_id:
        return []

    # 1. Exact catalog match
    matched = list(RULE_MITRE_CATALOG.get(rule_id, []))
    if matched:
        return matched

    # 2. Tag-based resolution
    for tag in tags:
        from_tag = get_mitre_techniques_by_tag(tag)
        if from_tag:
            return from_tag

    # 3. Fuzzy identifier match against catalog keys
    rule_id_clean = rule_id.lower().replace("-", "_").replace(" ", "_")
    for key, techs in RULE_MITRE_CATALOG.items():
        key_clean = key.lower().replace("-", "_").replace(" ", "_")
        if key_clean in rule_id_clean or rule_id_clean in key_clean:
            return techs

    return []
