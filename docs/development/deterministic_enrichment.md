# Deterministic Enrichment Engine

## 1. Purpose

The deterministic enrichment engine adds locally-derived contextual
information to a NormalizedSecurityEvent without calling any external
service, accessing a database, or making network requests.

Pipeline position:

```
SecurityEvent
    -> NormalizedSecurityEvent
        -> [Deterministic Enrichment Engine]  <- this module
            -> EnrichedSecurityEvent
                -> Future Detection
```

## 2. Why Enrichment Follows Normalization

- **Normalization**: "What does the raw event mean?"
- **Deterministic enrichment**: "What additional context can we derive locally?"
- **Threat intelligence**: "What does an external intelligence source tell us?"
- **Synthetic reconstruction**: "What information can we carefully infer?"

These are separate concepts with distinct trust semantics.

## 3. Deterministic Enrichment Philosophy

The enrichments produced by this engine are:

- **Deterministic**: same input always produces the same output.
- **Stateless**: no instance state is mutated between calls.
- **Side-effect free**: no network, database, or filesystem access.
- **Input-immutable**: the original NormalizedSecurityEvent is never modified.

This is explicitly NOT threat intelligence, reputation scoring, or
behavioral analysis. It is simple contextual labelling derived from
established standards.

## 4. Supported Enrichment Types

| Enrichment Type      | Description                                |
|----------------------|--------------------------------------------|
| `ip_classification`  | IP address scope classification            |
| `service_context`    | Port-to-service mapping                    |
| `file_type_context`  | File extension categorization              |
| `process_context`    | Process name categorization                |

## 5. IP Classification

For source and destination IP addresses, the engine classifies
using Python's `ipaddress` standard library:

| Classification | Examples |
|---------------|----------|
| `loopback`    | 127.0.0.1, ::1 |
| `link_local`  | 169.254.x.x, fe80::/10 |
| `multicast`   | 224.x.x.x, ff00::/8 |
| `unspecified` | 0.0.0.0, :: |
| `private`     | 10.x.x.x, 172.16-31.x.x, 192.168.x.x |
| `reserved`    | IANA-reserved ranges |
| `public`      | All other globally-routable addresses |

Classification describes address scope, NOT reputation.

## 6. Service/Port Context

Well-known ports are mapped to service names (IANA conventions):

- 22 -> ssh, 80 -> http, 443 -> https, 53 -> dns, 3389 -> rdp
- 3306 -> mysql, 5432 -> postgresql, 6379 -> redis
- ...and 25+ others

Unknown ports produce no enrichment. Service name is contextual
information, not a security assessment.

## 7. File Context

File extensions map to type categories:

- `.exe` -> executable, `.ps1` -> powershell_script
- `.sh` -> shell_script, `.py` -> python_script
- `.dll` -> library, `.txt` -> text, `.log` -> log_file
- ...and 60+ others

Unknown extensions produce no enrichment.

## 8. Process Context

Process names are classified into categories:

- `powershell.exe` -> scripting_interpreter
- `cmd.exe` -> command_shell, `bash` -> shell
- `python` -> interpreter, `ssh` -> remote_access
- `curl` -> network_utility, `whoami.exe` -> system_utility
- ...and 40+ others

## 9. Provenance Semantics

- EnrichedSecurityEvent: `provenance = ENRICHED`
- Original NormalizedSecurityEvent: provenance preserved (typically OBSERVED)
- Each EnrichmentResult: `source = "sentinelai_deterministic_rules"`
- `RECONSTRUCTED` is never assigned by this engine
- `confidence` is `None` (deterministic, not probabilistic)

## 10. Immutability

The input NormalizedSecurityEvent is never modified. Tests verify that
all fields (endpoints, process, file, normalized_data, provenance)
remain unchanged after enrichment.

## 11. Determinism

The engine does not use: randomness, LLMs/AI, external APIs, network
requests, current-time-dependent logic, or environment-dependent logic.

## 12. Missing-Data Behavior

No data is fabricated. Missing fields produce no enrichment for that
category.

## 13. Invalid-Data Behavior

Invalid data is handled gracefully:
- Invalid IP ("not-an-ip") -> silently skipped
- Invalid port (-1, 99999) -> silently skipped
- Unknown extension (".xyzzy") -> silently skipped
- Unknown process ("random_bin") -> silently skipped
- Single rule failure never crashes the entire enrichment

## 14. Why This Is NOT Threat Intelligence

| Concept | Deterministic Enrichment | Threat Intelligence |
|---------|--------------------------|---------------------|
| IP address | "private", "loopback"   | "Known C2 server"   |
| Port     | "ssh", "http"           | "Commonly exploited" |
| File ext | "executable", "script"  | "Distributes malware" |
| Process  | "interpreter", "shell"  | "LOLBin"            |

## 15. Future Provider Integration Boundary

The rule-based architecture (EnrichmentRule ABC) accommodates future
providers:

```python
agent = EnrichmentAgent(rules=[
    IPClassificationRule(),
    ServiceContextRule(),
    FileTypeContextRule(),
    ProcessContextRule(),
    # Future: VirusTotalRule(), AbuseIPDBRule(), etc.
])
```

Future steps will add: VirusTotal, AbuseIPDB, AlienVault OTX,
geolocation, DNS/WHOIS, asset inventory, and reputation scoring.
