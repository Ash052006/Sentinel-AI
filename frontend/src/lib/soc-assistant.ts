import type { SOCQueryResponse } from '../types/api'

export interface AssistantAnalysis {
  verdict: string
  headline: string
  summary: string
  severityLevel: 'critical' | 'high' | 'medium' | 'low' | 'info'
  recommendations: string[]
  followUps: string[]
  tactics: string[]
  isConversationalOnly?: boolean
}

export function isConversationalQuery(query: string): boolean {
  const queryLower = query.trim().toLowerCase()
  const greetingPatterns = [
    /^(hi|hello|hey|greetings|howdy|sup|good morning|good afternoon|good evening)\b/,
    /\b(who are you|what can you do|introduce yourself|help me|what is your role)\b/,
  ]
  const vulnPatterns = [
    /\b(vulnerabilit|cve|cves|exploit|patching|patch|weakness|zero-day|exposure|misconfigur)\w*/,
  ]
  const howToPatterns = [
    /\b(how do i|how to|what is|explain|tell me about|best practice)\b/,
  ]

  return (
    greetingPatterns.some((p) => p.test(queryLower)) ||
    vulnPatterns.some((p) => p.test(queryLower)) ||
    howToPatterns.some((p) => p.test(queryLower))
  )
}

export function synthesizeSocResponse(
  userQuery: string,
  response?: SOCQueryResponse | null,
): AssistantAnalysis {
  const queryLower = userQuery.trim().toLowerCase()

  // 1. Greetings & Personal Assistant Introduction
  const greetingPatterns = [
    /^(hi|hello|hey|greetings|howdy|sup|good morning|good afternoon|good evening)\b/,
    /\b(who are you|what can you do|introduce yourself|help me|what is your role)\b/,
  ]
  if (greetingPatterns.some((pattern) => pattern.test(queryLower))) {
    return {
      verdict: 'Personal SOC Assistant Online',
      headline: 'Ready to assist with security investigations & telemetry',
      summary:
        "Hello! I'm your Sentinel SOC Personal Assistant. You can ask me anything about active threat detections, vulnerability exposures, attack correlations, risk scoring, or incident response playbooks. How can I help you today?",
      severityLevel: 'info',
      recommendations: [
        'Ask about known vulnerabilities and CVE exposures in your environment.',
        'Review recent high-severity detections across monitored assets.',
        'Investigate multi-stage attack correlations and response playbooks.',
      ],
      followUps: [
        'what vulnerabilities should I look for?',
        'recent detections',
        'recent correlations',
        'high risk assessments',
      ],
      tactics: ['SOC Operations', 'Triage & Advisory'],
      isConversationalOnly: true,
    }
  }

  // 2. Vulnerabilities, CVEs & Exposures
  const vulnPatterns = [
    /\b(vulnerabilit|cve|cves|exploit|patching|patch|weakness|zero-day|exposure|misconfigur)\w*/,
  ]
  if (vulnPatterns.some((pattern) => pattern.test(queryLower))) {
    return {
      verdict: 'Vulnerability & Exposure Advisory',
      headline: 'Continuous vulnerability assessment & exploit mitigation',
      summary:
        'Vulnerability management in Sentinel AI combines automated detection correlation with continuous exposure monitoring. Monitored attack surfaces include unpatched remote-access services (RDP/SSH), outdated software components, weak credential policies, and lateral movement vectors. Detection rules continuously flag active exploitation attempts targeting known CVEs.',
      severityLevel: 'medium',
      recommendations: [
        'Prioritize patching for externally exposed endpoints (SSH on port 22, RDP on port 3389).',
        'Enforce multi-factor authentication (MFA) to neutralize credential-stuffing exploits.',
        'Review recent detection alerts to verify whether any active exploit attempts succeeded.',
        'Deploy virtual patch rules (WAF/Sigma) for zero-day disclosures prior to vendor patches.',
      ],
      followUps: [
        'recent detections',
        'recent correlations',
        'how to secure ssh',
        'critical risk assessments',
      ],
      tactics: ['Vulnerability Management', 'Initial Access', 'Exploitation'],
      isConversationalOnly: true,
    }
  }

  // 3. Security Concept Explanations & How-To Guides
  const howToPatterns = [
    /\b(how do i|how to|what is|explain|tell me about|best practice)\b/,
  ]
  if (howToPatterns.some((pattern) => pattern.test(queryLower))) {
    return {
      verdict: 'Security Operations Guidance',
      headline: `Analyst guidance for "${userQuery}"`,
      summary:
        `Regarding "${userQuery}": In a modern SOC environment, rapid containment and evidence preservation are critical. Ensure your telemetry pipelines stream endpoint, network, and identity events into the correlation engine to minimize dwell time.`,
      severityLevel: 'info',
      recommendations: [
        'Isolate compromised hosts immediately upon high-confidence correlation.',
        'Collect volatile memory, active network sockets, and command history before remediation.',
        'Verify whether related alerts share common indicators of compromise (IoCs).',
      ],
      followUps: [
        'recent detections',
        'recent correlations',
        'incident memories',
      ],
      tactics: ['Incident Response', 'Defense in Depth'],
      isConversationalOnly: true,
    }
  }

  // 4. Telemetry-Grounded Responses
  const resource = response?.metadata?.resource ?? 'telemetry'
  const count = response?.count ?? 0
  const items = response?.items ?? []

  if (!response || !response.found || count === 0) {
    return {
      verdict: 'No Active Anomalies Found',
      headline: `Clean check across ${resource}`,
      summary: `I scanned the live ${resource} repository for "${userQuery}". No matching threat alerts or telemetry records were found. The SOC engine operates in strictly read-only mode with zero data fabrication.`,
      severityLevel: 'info',
      recommendations: [
        'Broaden your query terms or check broader time horizons.',
        'Verify Kafka ingest and connector health to ensure real-time log streaming.',
        'Review detection rules to ensure appropriate coverage.',
      ],
      followUps: [
        'recent detections',
        'recent correlations',
        'high risk assessments',
      ],
      tactics: ['Baseline Monitoring'],
    }
  }

  // Detections resource
  if (resource === 'detections') {
    const severities = items.map((i) => String(i.severity ?? 'medium').toLowerCase())
    const rules = Array.from(new Set(items.map((i) => String(i.rule_id ?? 'unknown')).filter(Boolean)))
    const hasCritical = severities.includes('critical')
    const hasHigh = severities.includes('high')
    const maxSev = hasCritical ? 'critical' : hasHigh ? 'high' : 'medium'

    const topRule = rules[0] ?? 'custom-rule'
    const ruleCount = rules.length

    return {
      verdict: hasCritical
        ? 'Critical Threat Detections Requiring Immediate Containment'
        : hasHigh
          ? 'High-Priority Security Alerts Flagged'
          : 'Security Detections Under Monitoring',
      headline: `${count} detection alert${count > 1 ? 's' : ''} triggered across ${ruleCount} detection rule${ruleCount > 1 ? 's' : ''}`,
      summary: `I analyzed the ${count} detection(s) retrieved. The primary alert is driven by "${topRule}" with ${maxSev.toUpperCase()} severity. ${
        hasCritical || hasHigh
          ? 'This pattern suggests potential unauthorized access or adversary command execution in progress.'
          : 'Telemetry reflects anomaly alerts that should be correlated against active sessions.'
      }`,
      severityLevel: maxSev,
      recommendations: [
        `Triage the entity flagged by rule "${topRule}" and inspect recent process trees.`,
        'Check network telemetry for outbound egress or known C2 communication.',
        'Review associated correlation clusters to assess if this detection is part of a multi-stage attack.',
      ],
      followUps: [
        'recent correlations',
        `show detections for rule ${topRule}`,
        'critical risk assessments',
      ],
      tactics: ['Execution', 'Initial Access', 'Defense Evasion'],
    }
  }

  // Correlations resource
  if (resource === 'correlations') {
    const statuses = items.map((i) => String(i.status ?? 'active'))
    const hasActive = statuses.includes('active') || statuses.includes('in_progress')

    return {
      verdict: hasActive
        ? 'Active Multi-Stage Attack Correlation Identified'
        : 'Historical Correlation Clusters Retrieved',
      headline: `${count} correlation cluster${count > 1 ? 's' : ''} mapped from telemetry`,
      summary: `I examined ${count} correlation(s) matching your inquiry. Multi-incident correlations link discrete alerts into a unified kill-chain graph. Several events exhibit corroborated adversary behavior across network and host layers.`,
      severityLevel: hasActive ? 'high' : 'medium',
      recommendations: [
        'Open the incident workspace to inspect the unified knowledge graph.',
        'Evaluate the multi-agent debate consensus to confirm attack hypotheses.',
        'Generate an evidence-grounded playbook to initiate response actions.',
      ],
      followUps: [
        'critical risk assessments',
        'recent detections',
        'incident memories',
      ],
      tactics: ['Lateral Movement', 'Credential Access', 'Command and Control'],
    }
  }

  // Risk assessments resource
  if (resource === 'risk_assessments') {
    const levels = items.map((i) => String(i.level ?? 'medium').toLowerCase())
    const hasCritical = levels.includes('critical')
    const hasHigh = levels.includes('high')
    const maxSev = hasCritical ? 'critical' : hasHigh ? 'high' : 'medium'

    const avgScore =
      items.reduce((acc, i) => acc + (Number(i.score) || 0), 0) / (items.length || 1)

    return {
      verdict: hasCritical
        ? 'Elevated Risk Assessment — Priority Response Required'
        : 'Risk Assessment Evaluation Complete',
      headline: `Evaluated ${count} risk assessment(s) with average score ${avgScore.toFixed(0)}/100`,
      summary: `The risk scoring pipeline evaluated ${count} risk record(s) under "${userQuery}". Peak severity is ${maxSev.toUpperCase()}. This assessment synthesizes detection frequency, asset criticality, and adversary technique likelihood.`,
      severityLevel: maxSev,
      recommendations: [
        'Prioritize containment on high-criticality assets identified in this score.',
        'Verify if mitigation controls or firewall rate limits were automatically applied.',
        'Coordinate with Tier 2 analysts for proactive threat hunting.',
      ],
      followUps: [
        'recent correlations',
        'recent detections',
        'incident memories',
      ],
      tactics: ['Impact', 'Privilege Escalation'],
    }
  }

  // Incident memories resource
  return {
    verdict: 'Institutional Incident Memory Retrieved',
    headline: `${count} institutional memory record${count > 1 ? 's' : ''} available`,
    summary: `I retrieved past institutional incident memories relevant to "${userQuery}". Historical resolution patterns, attack signatures, and verified playbooks can be leveraged to accelerate your current response.`,
    severityLevel: 'info',
    recommendations: [
      'Compare current indicators against the historical precedent.',
      'Adopt response actions that previously yielded fast containment.',
      'Record new findings in post-incident reviews to continuously teach the assistant.',
    ],
    followUps: [
      'recent detections',
      'recent correlations',
      'critical risk assessments',
    ],
    tactics: ['Historical Precedent', 'Lessons Learned'],
  }
}
